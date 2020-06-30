using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using AzureIpRangeValidator.Extension;

namespace AzureIpRangeValidator
{
    public class LogParser
    {
        private ConcurrentDictionary<string, AzureServiceTag> _consolidatedAzureTraffic = new ConcurrentDictionary<string, AzureServiceTag>();
        private AzureServiceTag _consolidatedNonAzureTraffic = new AzureServiceTag();

        public int TotalHitCount 
        {
            get
            {
                return AzureHitCount + NonAzureHitCount;
            } 
        }

        public int AzureHitCount
        {
            get
            {
                int result = 0;
                foreach (var element in _consolidatedAzureTraffic)
                {
                    result += element.Value.TotalHitCount;
                }
                return result;
            }
        }

        public int NonAzureHitCount
        {
            get
            {
                return _consolidatedNonAzureTraffic.TotalHitCount;
            }
        }

        public LogParser()
        {
            _consolidatedNonAzureTraffic.Tag = "NON-AZURE TRAFFIC";
        }

        public Dictionary<string, AzureServiceTag> ReportMatchForAzureIp(
            string ipAddress, 
            string subnet, 
            Value serviceType, 
            FirewallLogEntry entry, 
            IPNetwork networkInfo,
            Dictionary<string, AzureServiceTag> hitsPerIp)
        {
            AzureServiceTag azureService;

            if (hitsPerIp.ContainsKey(subnet))
            {
                azureService = hitsPerIp[subnet];
            }
            else
            {
                azureService = new AzureServiceTag();
            }

            azureService.Tag = TakeTheMostRelevantValue(serviceType.name, azureService.Tag);
            azureService.IpRange = TakeTheMostRelevantValue(subnet, azureService.IpRange);
            azureService.CIDR = networkInfo.Cidr;
            azureService.Region = TakeTheMostRelevantValue(serviceType.properties.region, azureService.Region);
            azureService.AzureService = TakeTheMostRelevantValue(serviceType.properties.systemService, azureService.AzureService);

            azureService.AddMatchedIp(ipAddress, entry.TimesBlocked, entry.DestinationIP);

            hitsPerIp[subnet] = azureService;

            return hitsPerIp;
        }

        public void ConsolidateResultsForAzureIP(Dictionary<string, AzureServiceTag> _hitsPerIp)
        {
            var mostSpecificServiceTag = _hitsPerIp
                .ToList()
                .OrderByDescending(e => e.Value.CIDR)
                .ToList()
                .FirstOrDefault();

            _hitsPerIp.Clear();

            if (_consolidatedAzureTraffic.ContainsKey(mostSpecificServiceTag.Key))
            {
                var azureService = _consolidatedAzureTraffic[mostSpecificServiceTag.Key];

                if (mostSpecificServiceTag.Value.Matches.Count != 1)
                    throw new System.Exception("Inconsistent parsing");

                var match = mostSpecificServiceTag.Value.Matches.FirstOrDefault().Value;

                azureService.AddMatchedIp(match.IpAddress, match.HitCount, match.Description);
                _consolidatedAzureTraffic[mostSpecificServiceTag.Key] = azureService;
            }
            else
            {
                _consolidatedAzureTraffic[mostSpecificServiceTag.Key] = mostSpecificServiceTag.Value;
            }
        }

        private string TakeTheMostRelevantValue(string newValue, string originalValue)
        {
            if (newValue.IsEmpty() && originalValue.IsEmpty()) return null;
            if (newValue.IsEmpty() && originalValue.IsNotEmpty()) return originalValue;
            if (newValue.IsNotEmpty() && originalValue.IsEmpty()) return newValue;
            if (newValue.IsLongerThan(originalValue)) return newValue;

            return originalValue;
        }

        public void ReportNonAzureIP(string ipAddress, FirewallLogEntry entry)
        {
            _consolidatedNonAzureTraffic.AddMatchedIp(ipAddress, entry.TimesBlocked, entry.DestinationIP);
        }

        public List<KeyValuePair<string, AzureServiceTag>> GetAzureIps()
        {
            var sortedLogs =
                _consolidatedAzureTraffic
                .ToList()
                .OrderByDescending(e => e.Value.TotalHitCount)
                .ToList();

            return sortedLogs;
        }

        public AzureServiceTag GetNonAzureIps()
        {
            return _consolidatedNonAzureTraffic;
        }
    }
}
