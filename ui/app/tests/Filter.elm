module Filter exposing (generateQueryString, parseMatcher, stringifyFilter)

import Expect
import Fuzz exposing (int, list, string, tuple)
import Helpers exposing (isNotEmptyTrimmedAlphabetWord)
import Test exposing (..)
import Utils.Filter exposing (MatchOperator(..), Matcher)


parseMatcher : Test
parseMatcher =
    describe "parseMatcher"
        [ test "should parse empty matcher string" <|
            \() ->
                Expect.equal Nothing (Utils.Filter.parseMatcher "")
        , test "should parse empty matcher value" <|
            \() ->
                Expect.equal (Just (Matcher "alertname" Eq "")) (Utils.Filter.parseMatcher "alertname=\"\"")
        , fuzz (tuple ( string, string )) "should parse random matcher string" <|
            \( key, value ) ->
                if List.map isNotEmptyTrimmedAlphabetWord [ key, value ] /= [ True, True ] then
                    Expect.equal
                        Nothing
                        (Utils.Filter.parseMatcher <| String.join "" [ key, "=", value ])

                else
                    Expect.equal
                        (Just (Matcher key Eq value))
                        (Utils.Filter.parseMatcher <| String.join "" [ key, "=", "\"", value, "\"" ])
        ]


generateQueryString : Test
generateQueryString =
    describe "generateQueryString"
        [ test "should not render keys with Nothing value except the silenced, inhibited, and active parameters, which default to false, false, true, respectively." <|
            \() ->
                Expect.equal "?silenced=false&inhibited=false&active=true"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Nothing, showSilenced = Nothing, showInhibited = Nothing, showActive = Nothing })
        , test "should not render filter key with empty value" <|
            \() ->
                Expect.equal "?silenced=false&inhibited=false&active=true"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Just "", showSilenced = Nothing, showInhibited = Nothing, showActive = Nothing })
        , test "should render filter key with values" <|
            \() ->
                Expect.equal "?silenced=false&inhibited=false&active=true&filter=%7Bfoo%3D%22bar%22%2C%20baz%3D~%22quux.*%22%7D"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Just "{foo=\"bar\", baz=~\"quux.*\"}", showSilenced = Nothing, showInhibited = Nothing, showActive = Nothing })
        , test "should render silenced key with bool" <|
            \() ->
                Expect.equal "?silenced=true&inhibited=false&active=true"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Nothing, showSilenced = Just True, showInhibited = Nothing, showActive = Nothing })
        , test "should render inhibited key with bool" <|
            \() ->
                Expect.equal "?silenced=false&inhibited=true&active=true"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Nothing, showSilenced = Nothing, showInhibited = Just True, showActive = Nothing })
        , test "should render active key with bool" <|
            \() ->
                Expect.equal "?silenced=false&inhibited=false&active=false"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = False, text = Nothing, showSilenced = Nothing, showInhibited = Nothing, showActive = Just False })
        , test "should add customGrouping key" <|
            \() ->
                Expect.equal "?silenced=false&inhibited=false&active=true&customGrouping=true"
                    (Utils.Filter.generateQueryString { receiver = Nothing, group = Nothing, customGrouping = True, text = Nothing, showSilenced = Nothing, showInhibited = Nothing, showActive = Nothing })
        ]


stringifyFilter : Test
stringifyFilter =
    describe "stringifyFilter"
        [ test "empty" <|
            \() ->
                Expect.equal ""
                    (Utils.Filter.stringifyFilter [])
        , test "non-empty" <|
            \() ->
                Expect.equal "{foo=\"bar\", baz=~\"quux.*\"}"
                    (Utils.Filter.stringifyFilter
                        [ { key = "foo", op = Eq, value = "bar" }
                        , { key = "baz", op = RegexMatch, value = "quux.*" }
                        ]
                    )
        ]
