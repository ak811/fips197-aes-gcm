package io.github.ak811.aes.cli;

/** Entry point for {@code java -jar aesf.jar}. */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        int code = new Cli(System.in, System.out, System.err, System.getenv()).run(args);
        System.out.flush();
        System.exit(code);
    }
}
