using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CloudflareJwtValidator.Models
{
    public enum MatchingMode : byte
    {
        /// <summary>
        /// Will match all values except for the ones listed.
        /// </summary>
        Exclude = 0,

        /// <summary>
        /// Will only match when an exact value is found in the array.
        /// </summary>
        Include = 1
    }

    public class StringMatchSettings
    {
        public const string kPatternWildcard = "*";

        public StringMatchSettings(MatchingMode matchingMode, params Regex[]? regexes)
        {
            if (regexes != null)
            {
                if (regexes.Any(IsNullOrEmpty))
                {
                    throw new ArgumentException($"'{nameof(regexes)}' must not contain null or whitspace matchingPatterns.", nameof(regexes));
                }

                if (regexes.Any(StartsOrEndsWithWhitespace))
                {
                    throw new ArgumentException($"'{nameof(regexes)}' must not contain matchingPatterns starting/ending with white spaces.", nameof(regexes));
                }
            }

            MatchingMode = matchingMode;
            Regexes = regexes;
        }

        public StringMatchSettings(MatchingMode matchingMode, params string[]? matchingPatterns)
            : this(
                matchingMode,
                matchingPatterns?.Select(
                    matchingPattern => new Regex(
                        "^" + Regex.Escape(matchingPattern).Replace($"\\{kPatternWildcard}", ".*?"),
                        RegexOptions.IgnoreCase
                    )
                )
                .ToArray()
            )
        { }

        public static StringMatchSettings IncludeAll => new StringMatchSettings(MatchingMode.Exclude, regexes: null);

        public static StringMatchSettings ExcludeAll => new StringMatchSettings(MatchingMode.Include, regexes: null);


        public static StringMatchSettings IncludeAllExcept(params string[]? matchingPatterns) => new StringMatchSettings(MatchingMode.Exclude, matchingPatterns);

        public static StringMatchSettings ExcludeAllExcept(params string[]? matchingPatterns) => new StringMatchSettings(MatchingMode.Include, matchingPatterns);


        public static StringMatchSettings IncludeAllExcept(params Regex[]? regexes) => new StringMatchSettings(MatchingMode.Exclude, regexes);

        public static StringMatchSettings ExcludeAllExcept(params Regex[]? regexes) => new StringMatchSettings(MatchingMode.Include, regexes);


        public MatchingMode MatchingMode { get; }

        public Regex[]? Regexes { get; }

        public IEnumerable<string> MatchingPatterns => Regexes?.Select(regex => regex.ToString()) ?? Enumerable.Empty<string>();

        
        private const string kRegexWhitespace = "\\s";

        private static bool IsNullOrEmpty(Regex regex)
        {
            var matchingPattern = regex.ToString();
            return string.IsNullOrEmpty(matchingPattern) || matchingPattern == kRegexWhitespace;
        }

        private static bool StartsOrEndsWithWhitespace(Regex regex)
        {
            var matchingPattern = regex.ToString();
            return matchingPattern.StartsWith(kRegexWhitespace) 
                || matchingPattern.StartsWith($"^{kRegexWhitespace}") 
                || matchingPattern.EndsWith(kRegexWhitespace);
        }

        
        internal bool IsMatch(string testValue)
        {
            if (Regexes is null || Regexes.Length == 0)
            {
                return MatchingMode switch
                {
                    MatchingMode.Exclude => true,
                    MatchingMode.Include => false,
                    _ => throw new NotImplementedException($"Missing case for {nameof(Models.MatchingMode)}.{MatchingMode}")
                };
            }

            bool IsMatchingValue(Regex regex) => regex.IsMatch(testValue);

            bool IsNotMatchingValue(Regex regex) => !IsMatchingValue(regex);

            return MatchingMode switch
            {
                MatchingMode.Exclude => Regexes.All(IsNotMatchingValue),
                MatchingMode.Include => Regexes.Any(IsMatchingValue),
                _ => throw new NotImplementedException($"Missing case for {nameof(Models.MatchingMode)}.{MatchingMode}")
            };
        }
    }
}