# RIPE Database templates

The output of `whois -h whois.ripe.net -t <class>` for each class the RIPE
profile covers (attribute lines only), fetched 2026-09-22.
`TestRIPEProfileMatchesTemplates` checks `object.RIPE` against these files, and
the live `TestRIPETemplatesAreCurrent` (`RPSL_LIVE=1`) checks them against the
RIPE Database, so a template change there shows up as a test failure here.

Refresh with:

    for c in $(ls *.txt | sed 's/.txt$//'); do
      whois -h whois.ripe.net -t $c | grep -E '^[a-z0-9-]+:[[:space:]]*\[' > $c.txt
    done
