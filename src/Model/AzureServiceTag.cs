using System.Collections.Generic;

namespace AzureIpRangeValidator
{
    public class AzureServiceTag
    {
        public AzureServiceTag()
        {
            TotalHitCount = 0;
            Matches = new Dictionary<string, IpAddressInfo>();
        }

        public string Tag { get; set; }
        public string Region { get; set; }
        public string AzureService { get; set; }
        public string IpRange { get; set; }
        public byte CIDR { get; set; }
        public int TotalHitCount { get; private set; }
        public Dictionary<string, IpAddressInfo> Matches { get; }

        public void AddMatchedIp(string ipAddress, int hitCount, string firewalLogDestIpContent)
        {
            if (Matches.ContainsKey(firewalLogDestIpContent))
                return;
            
            Matches.Add(firewalLogDestIpContent, new IpAddressInfo(ipAddress, hitCount, firewalLogDestIpContent));
            this.TotalHitCount += hitCount;
        }
    }
}