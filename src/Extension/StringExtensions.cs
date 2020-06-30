namespace AzureIpRangeValidator.Extension
{
    public static class StringExtensions
    {
        public static bool IsEmpty(this string str)
        {
            return string.IsNullOrWhiteSpace(str);
        }

        public static bool IsNotEmpty(this string str)
        {
            return !string.IsNullOrWhiteSpace(str);
        }

        public static bool IsLongerThan(this string str, string str2)
        {
            return str.Length > str2.Length;
        }
    }
}
