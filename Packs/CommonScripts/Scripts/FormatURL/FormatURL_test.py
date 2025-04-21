import demistomock as demisto
import FormatURL


def test_formatter(mocker):
    mocker.patch.object(demisto, "args", return_value={"input": "https://www.test.com"})
    mocker.patch.object(demisto, "results")

    FormatURL.main()

    results = demisto.results.call_args[0]

    assert results[0]["Contents"] == ["https://www.test.com"]


def test_failed_formatter(mocker):
    mocker.patch.object(demisto, "args", return_value={"input": "https://@www.test.com"})
    mocker.patch.object(demisto, "results")

    FormatURL.main()

    results = demisto.results.call_args[0]

    assert results[0]["Contents"] == [""]


def test_bad(mocker):
    mocker.patch.object(demisto, "args", return_value={"input": 1})
    return_error = mocker.patch.object(FormatURL, "return_error")
    FormatURL.main()
    return_error.assert_called_once()


def test_proofpoint_v3(mocker):
    """Given
        - A Proofpoint v3 URL as input.

    When
        - The FormatURL.main() function is executed.

    Then
        - The extracted URL should be correctly formatted.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "input": "https://urldefense.com/v3/__https://google.com:443/search?q=a*test&gs=ps__;Kw!-612Flbf0JvQ3kNJkRi5Jg!Ue6tQudNKaShHg93trcdjqDP8se2ySE65jyCIe2K1D_uNjZ1Lnf6YLQERujngZv9UWf66ujQIQ$"
        },
    )
    mock_result = mocker.patch.object(demisto, "results")
    FormatURL.main()
    assert mock_result.call_args[0][0]["Contents"][0] == "https://google.com:443/search?q=a+test&gs=ps"


def test_proofpoint_v1(mocker):
    """Given
        - A Proofpoint v1 URL as input.

    When
        - The FormatURL.main() function is executed.

    Then
        - The extracted URL should be correctly formatted.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "input": "https://urldefense.proofpoint.com/v1/url?u=http://www.bouncycastle.org/&amp;k=oIvRg1%2BdGAgOoM1BIlLLqw%3D%3D%0A&amp;r=IKM5u8%2B%2F%2Fi8EBhWOS%2BqGbTqCC%2BrMqWI%2FVfEAEsQO%2F0Y%3D%0A&amp;m=Ww6iaHO73mDQpPQwOwfLfN8WMapqHyvtu8jM8SjqmVQ%3D%0A&amp;s=d3583cfa53dade97025bc6274c6c8951dc29fe0f38830cf8e5a447723b9f1c9a"
        },
    )
    mock_result = mocker.patch.object(demisto, "results")
    FormatURL.main()
    assert mock_result.call_args[0][0]["Contents"][0] == "http://www.bouncycastle.org/"


def test_proofpoint_v2(mocker):
    """Given
        - A Proofpoint v2 URL as input.

    When
        - The FormatURL.main() function is executed.

    Then
        - The extracted URL should be correctly formatted.
    """
    mocker.patch.object(
        demisto,
        "args",
        return_value={
            "input": "https://urldefense.proofpoint.com/v2/url?u=https-3A__media.mnn.com_assets_images_2016_06_jupiter-2Dnasa.jpg.638x0-5Fq80-5Fcrop-2Dsmart.jpg&amp;d=DwMBaQ&amp;c=Vxt5e0Osvvt2gflwSlsJ5DmPGcPvTRKLJyp031rXjhg&amp;r=BTD8MPjq1qSLi0tGKaB5H6aCJZZBjwYkLyorZdRQrnY&amp;m=iKjixvaJuqvmReS78AB0JiActTrR_liSq7lDRjEQ9DE&amp;s=-M8Vz-GV-kqkNVf1BAtv38DdudAHVDAI6_jQQLVmleE&amp;e="
        },
    )
    mock_result = mocker.patch.object(demisto, "results")
    FormatURL.main()
    assert (
        mock_result.call_args[0][0]["Contents"][0]
        == "https://media.mnn.com/assets/images/2016/06/jupiter-nasa.jpg.638x0_q80_crop-smart.jpg"
    )
