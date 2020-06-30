using System.Collections.Generic;

namespace AzureIpRangeValidator
{
    class AzureIpRange
    {
        public int changeNumber { get; set; }
        public string cloud { get; set; }
        public List<Value> values { get; set; }
    }

    public class Value
    {
        public string name { get; set; }
        public string id { get; set; }
        public Properties properties { get; set; }
    }

    public class Properties
    {
        public int changeNumber { get; set; }
        public string region { get; set; }
        public string platform { get; set; }
        public string systemService { get; set; }
        public List<string> addressPrefixes { get; set; }
    }   
}