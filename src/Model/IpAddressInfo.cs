namespace AzureIpRangeValidator
{
    public class IpAddressInfo
    {
        public IpAddressInfo(string ipAddress, int hitCount, string description)
        {
            this.IpAddress = ipAddress;
            this.HitCount = hitCount;
            this.Description = description;
        }

        public string IpAddress { get; set; }
        public int HitCount { get; set; }
        public string Description { get; set; }
    }
}
