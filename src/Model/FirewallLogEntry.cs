namespace AzureIpRangeValidator
{
    public class FirewallLogEntry
    {
        public string DestinationIP { get; set; }
        public int TimesBlocked { get; set; }
    }
}