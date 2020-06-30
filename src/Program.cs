using CommandLine;
using CsvHelper;
using CsvHelper.Configuration;
using Newtonsoft.Json;
using ShellProgressBar;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AzureIpRangeValidator
{
    public class Options
    {
        [Option("logfile", Required = true, HelpText = "Full path to log file to be parsed in CSV format")]
        public string LogFile { get; set; }

        [Option("servicetagfile", Required = true, HelpText = "Full path to Azure Service Tag JSON")]
        public string AzureServiceTagsJson { get; set; }

        [Option('v', "verbose", Required = false, Default = false, HelpText = "Verbose mode for troubleshooting errors")]
        public bool Verbose { get; set; }

        [Option('t', "tab", Required = false, Default = false, HelpText = "Use tab (\\t) as delimiter for the CSV file, the default is a semicolon")]
        public bool UseTabDelimiter { get; set; }

        [Option('c', "comma", Required = false, Default = false, HelpText = "Use comma (,) as delimiter for the CSV file (default is semicolon")]
        public bool UseCommaDelimiter { get; set; }
    }

    class Program
    {
        private static Options _options;

        static async Task Main(string[] args)
        {
            var numThreads = Environment.ProcessorCount * 2;
            ThreadPool.SetMinThreads(numThreads, numThreads);

            await Parser.Default
                .ParseArguments<Options>(args)
                .WithParsedAsync(async opts => await DoWork(opts));
        }

        private async static Task DoWork(Options options)
        {
            _options = options;
            var foregroundColor = Console.ForegroundColor;

            try
            {
                AzureIpRange ipAddresses;

                using (StreamReader file = File.OpenText(options.AzureServiceTagsJson))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    ipAddresses = (AzureIpRange)serializer.Deserialize(file, typeof(AzureIpRange));
                }

                List<FirewallLogEntry> _firewallLogs;

                using (var reader = new StreamReader(options.LogFile))
                using (var csv = new CsvReader(reader, CultureInfo.InvariantCulture))
                {
                    if (_options.UseTabDelimiter)
                        csv.Configuration.Delimiter = "\t";
                    else if (_options.UseCommaDelimiter)
                        csv.Configuration.Delimiter = ",";
                    else
                        csv.Configuration.Delimiter = ";";

                    csv.Configuration.IgnoreBlankLines = true;
                    csv.Configuration.TrimOptions = TrimOptions.Trim;

                    _firewallLogs = csv.GetRecords<FirewallLogEntry>().ToList();
                }

                var _logParser = new LogParser();
                int _hitCounter = 0;
                var tasks = new List<Task>();

                using (var progressBar = new ProgressBar(_firewallLogs.Count, "Analyzing logs"))
                {
                    foreach (var firewallLogEntry in _firewallLogs)
                    {
                        if (options.Verbose)
                        {
                            _hitCounter += firewallLogEntry.TimesBlocked;
                            await ProcessFirewallLogEntry(ipAddresses, _logParser, _hitCounter, firewallLogEntry);
                            progressBar.Tick();
                        }
                        else
                        {
                            _hitCounter += firewallLogEntry.TimesBlocked;
                            tasks.Add(ProcessFirewallLogEntry(ipAddresses, _logParser, _hitCounter, firewallLogEntry));
                        }
                    }

                    while (tasks.Any(t => t.IsCompleted == false))
                    {
                        var task = await Task.WhenAny(tasks);
                        tasks.Remove(task);
                        progressBar.Tick();
                    }
                }

                await Task.WhenAll(tasks);


                Console.ForegroundColor = foregroundColor;
                Console.WriteLine($"Total Hit Count: {_logParser.TotalHitCount} | Azure: {_logParser.AzureHitCount} | Non-Azure: {_logParser.NonAzureHitCount}");
                Console.WriteLine($"CSV Parser Hit Count: {_hitCounter}");

                foreach (var item in _logParser.GetAzureIps())
                {
                    Console.WriteLine("");
                    Console.WriteLine($"{item.Value.Tag} | {item.Value.Region} | {item.Value.IpRange} | {item.Value.AzureService} | Total Hits: {item.Value.TotalHitCount}");

                    foreach (var ip in item.Value.Matches)
                    {
                        Console.WriteLine($"     {ip.Key} | {ip.Value.HitCount}");
                    }
                }

                var nonAzureIp = _logParser.GetNonAzureIps();
                Console.WriteLine("");
                Console.WriteLine($"{nonAzureIp.Tag} | Total Hits: {nonAzureIp.TotalHitCount}");

                foreach (var ip in nonAzureIp.Matches)
                {
                    Console.WriteLine($"     {ip.Key} | {ip.Value.HitCount}");
                }
            }
            catch (Exception ex)
            {
                Console.Write(ex);
            }
        }

        private static async Task ProcessFirewallLogEntry(AzureIpRange ipAddresses, LogParser _logParser, int _hitCounter, FirewallLogEntry firewallLogEntry)
        {
            Regex extractIpAddress = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
            MatchCollection ipAddressFromRegex = extractIpAddress.Matches(firewallLogEntry.DestinationIP);
            if (ipAddressFromRegex.Count == 0)
            {
                Console.WriteLine($"Error: unable to parse log entry: '{firewallLogEntry.DestinationIP}'");
                return;
            }

            var cleanIpAddress = ipAddressFromRegex[0].Value;
            var hitsPerIp = new Dictionary<string, AzureServiceTag>();

            bool isAzureIp = false;

            await Task.Run(() =>
            {
                IPAddress ipAdress;
                if (IPAddress.TryParse(cleanIpAddress, out ipAdress))
                {
                    foreach (var serviceType in ipAddresses.values)
                    {
                        foreach (var subnet in serviceType.properties.addressPrefixes)
                        {
                            var subnetInfo = IPNetwork.Parse(subnet);

                            if (subnetInfo.Contains(ipAdress))
                            {
                                isAzureIp = true;

                                hitsPerIp = _logParser.ReportMatchForAzureIp(
                                    cleanIpAddress,
                                    subnet,
                                    serviceType,
                                    firewallLogEntry,
                                    subnetInfo,
                                    hitsPerIp);
                            }
                        }
                    }
                }

                if (isAzureIp)
                {
                    _logParser.ConsolidateResultsForAzureIP(hitsPerIp);
                }

                if (!isAzureIp)
                {
                    _logParser.ReportNonAzureIP(
                                   cleanIpAddress,
                                   firewallLogEntry);
                }

                if (_options.Verbose && _logParser.TotalHitCount != _hitCounter)
                {
                    throw new Exception($"Inconsistency in stats generation while processing: {JsonConvert.SerializeObject(firewallLogEntry)}");
                }

            }).ConfigureAwait(false);
        }
    }
}