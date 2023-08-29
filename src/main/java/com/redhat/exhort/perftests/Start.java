package com.redhat.exhort.perftests;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpClient.Version;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.IntStream;

import com.redhat.exhort.Api;
import com.redhat.exhort.impl.ExhortApi;

import picocli.CommandLine;

@CommandLine.Command
public class Start implements Runnable {

    @CommandLine.Option(names = {"-r", "--requests"}, description = "Number of requests to run. Defaults to 20.", defaultValue = "1")
    Integer requests;

    @CommandLine.Option(names = {"-m", "--manifest"}, description = "Manifest file path to use when using the API (-a true). Defaults to pom.xml", defaultValue = "pom.xml")
    String manifestFile;

    @CommandLine.Option(names = {"-s", "--sbom"}, description = "Sbom file path to use when NOT using the API (-a false). Defaults to sbom.json", defaultValue = "sbom.json")
    String sbomFile;

    @CommandLine.Option(names = {"-v", "--verbose"}, description = "Show verbose output", defaultValue = "false")
    Boolean verbose;

    @CommandLine.Option(names = {"-a", "--use-api"}, description = "Use API. If true the manifest must be specified. If false then the sbom file is expected. Defaults to false", defaultValue = "false")
    Boolean useApi;

    @CommandLine.Option(names = {"-h", "--host"}, description = "Exhort API endpoint", defaultValue = "http://alpha-exhort.apps.sssc-cl01.appeng.rhecoeng.com/api/v3/analysis")
    String host;

    @Override
    public void run() {
        var exhortApi = new ExhortApi();
        CompletableFuture<Void>[] tasks = new CompletableFuture[requests];
        IntStream.range(0, requests).forEach(i -> {
            if(useApi) {
                tasks[i] = new MeasuredTask(exhortApi, i).stackAnalysis();
            } else {
                tasks[i] = new MeasuredTask(exhortApi, i).htmlRequest();
            }
        });
        try {
            CompletableFuture.allOf(tasks).get();
        } catch (InterruptedException | ExecutionException e) {
            throw new RuntimeException("Unable to process the stackAnalysis request", e);
        }
    }

    private class MeasuredTask {
        final Api exhortApi;
        final long id;
        final HttpClient client;
        final HttpRequest request;

        public MeasuredTask(ExhortApi exhortApi, long id) {
            this.exhortApi = exhortApi;
            this.id = id;
            this.client = HttpClient.newHttpClient();
            try {
                this.request = HttpRequest.newBuilder(URI.create(host))
                    .setHeader("Content-Type", "application/vnd.cyclonedx+json")
                    .setHeader("rhda-token", "foo")
                    .version(Version.HTTP_1_1)
                    .POST(HttpRequest.BodyPublishers.ofFile(new File(sbomFile).toPath()))
                    .build();
            } catch (FileNotFoundException e) {
                throw new RuntimeException("Unable to read SBOM file from: " + sbomFile, e);
            }
        }

        public CompletableFuture<Void> htmlRequest() {
            return CompletableFuture.supplyAsync(() -> {
                Long start = System.nanoTime();
                if (verbose) {
                    System.out.println(String.format("Task %d  started", id));
                }
                try {
                    client.send(request, HttpResponse.BodyHandlers.ofString());
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException("Unable to process HTTP Request", e);
                }
                if (verbose) {
                    System.out.println(String.format("Task %d  completed in %f s", id,
                            ((double) (System.nanoTime() - start)) / 1_000_000_000));
                }
                return null;
            });
        }

        public CompletableFuture<Void> stackAnalysis() {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    Long start = System.nanoTime();
                    if(verbose) {
                        System.out.println(String.format("Task %d  started", id));
                    }
                    exhortApi.stackAnalysis(manifestFile).get();
                    if(verbose) {
                        System.out.println(String.format("Task %d  completed in %f s", id,((double) (System.nanoTime() - start)) / 1_000_000_000));
                    }
                    return null;
                } catch (InterruptedException | ExecutionException | IOException e) {
                    throw new RuntimeException("Unable to perform stack analysis", e);
                }
            });
        }
    }

}
