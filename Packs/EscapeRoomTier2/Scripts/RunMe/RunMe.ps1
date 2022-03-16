function ThIsIsFuNpLeAsEfIxMe {
    $c = $env:g.Replace("@", "`n")
    $result = @{
            Type = 1;
            ContentsFormat = "markdown";
            Contents = $c;
            ReadableContentsFormat = "markdown";
            HumanReadable = $c
        }
    $demisto.Results($result)
}

ThIsIsFuNpLeeAsEfIxMe