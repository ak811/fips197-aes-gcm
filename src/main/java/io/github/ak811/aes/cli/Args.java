package io.github.ak811.aes.cli;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** A small, dependency-free parser for {@code --name value}, {@code --name=value} and flags. */
final class Args {

    private static final Map<String, String> ALIASES = Map.of("-o", "--output", "-f", "--force");

    private final List<String> positionals = new ArrayList<>();
    private final Map<String, String> options = new HashMap<>();
    private final Set<String> flags = new HashSet<>();

    private Args() {
    }

    static Args parse(List<String> tokens, Set<String> valueOptions, Set<String> flagOptions) throws UsageException {
        Args args = new Args();
        for (int i = 0; i < tokens.size(); i++) {
            String token = tokens.get(i);
            if (token.equals("--")) {
                args.positionals.addAll(tokens.subList(i + 1, tokens.size()));
                break;
            }
            if (!token.startsWith("-") || token.equals("-")) {
                args.positionals.add(token);
                continue;
            }
            String name = token;
            String value = null;
            int eq = token.indexOf('=');
            if (token.startsWith("--") && eq > 0) {
                name = token.substring(0, eq);
                value = token.substring(eq + 1);
            }
            name = ALIASES.getOrDefault(name, name);

            if (valueOptions.contains(name)) {
                if (value == null) {
                    if (i + 1 >= tokens.size()) {
                        throw new UsageException("missing value for " + name);
                    }
                    value = tokens.get(++i);
                }
                if (args.options.put(name, value) != null) {
                    throw new UsageException(name + " given more than once");
                }
            } else if (flagOptions.contains(name) && value == null) {
                args.flags.add(name);
            } else {
                throw new UsageException("unknown option " + token);
            }
        }
        return args;
    }

    String option(String name) {
        return options.get(name);
    }

    String option(String name, String defaultValue) {
        return options.getOrDefault(name, defaultValue);
    }

    boolean flag(String name) {
        return flags.contains(name);
    }

    List<String> positionals() {
        return positionals;
    }

    /** Exactly one positional argument, named {@code what} in error messages. */
    String single(String what) throws UsageException {
        if (positionals.size() != 1) {
            throw new UsageException("expected exactly one " + what + " argument, got " + positionals.size());
        }
        return positionals.get(0);
    }

    /** Parses an integer option; accepts K and M suffixes (binary multiples) when {@code size} is set. */
    int intOption(String name, int defaultValue, boolean size) throws UsageException {
        String raw = options.get(name);
        if (raw == null) {
            return defaultValue;
        }
        String s = raw.trim().replace("_", "").toUpperCase(Locale.ROOT);
        long multiplier = 1;
        if (size && s.endsWith("K")) {
            multiplier = 1024;
            s = s.substring(0, s.length() - 1);
        } else if (size && s.endsWith("M")) {
            multiplier = 1024 * 1024;
            s = s.substring(0, s.length() - 1);
        }
        try {
            long value = Long.parseLong(s) * multiplier;
            if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
                throw new NumberFormatException();
            }
            return (int) value;
        } catch (NumberFormatException e) {
            throw new UsageException("invalid number for " + name + ": " + raw);
        }
    }
}
