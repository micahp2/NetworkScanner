using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;
using NetworkScanner.Core;
using NetworkScanner.Services;

namespace NetworkScanner.Tests;

public class NetworkScannerTests
{
    [Theory]
    [InlineData("80,443", new[] { 80, 443 })]
    [InlineData("8080-8082", new[] { 8080, 8081, 8082 })]
    public void ParsePorts_Should_Work(string input, int[] expected)
    {
        var result = NetworkScannerUtils.ParsePorts(input);
        result.Should().BeEquivalentTo(expected);
    }

    [Fact]
    public void ExpandRange_Should_Support_Dash_Ranges()
    {
        var range = "192.168.1.1-192.168.1.3";
        var result = NetworkScannerUtils.ExpandRange(range);
        result.Should().ContainInOrder("192.168.1.1", "192.168.1.2", "192.168.1.3");
    }

    [Fact]
    public void Shuffle_Should_Randomize_Order_But_Keep_All_Elements()
    {
        var original = new List<int> { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var shuffled = new List<int>(original);
        
        NetworkScannerUtils.Shuffle(shuffled);
        
        shuffled.Should().BeEquivalentTo(original);
        shuffled.Should().NotEqual(original);
    }

    [Fact]
    public async Task ScanPortAsync_Should_ReturnTrue_ForOpenPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            _ = Task.Run(() => {
                try { using var s = listener.AcceptSocket(); } catch {}
            });

            var result = await NetworkScannerService.ScanPortAsync("127.0.0.1", port, 1000, CancellationToken.None);
            result.Should().BeTrue();
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ScanPortAsync_Should_ReturnFalse_ForClosedPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        int port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        var result = await NetworkScannerService.ScanPortAsync("127.0.0.1", port, 1000, CancellationToken.None);
        result.Should().BeFalse();
    }

    [Fact]
    public void IcmpPacket_Should_Serialize_And_Checksum_Correctly()
    {
        var packet = new IcmpPacket
        {
            Type = 8,
            Code = 0,
            Identifier = 0x1234,
            Sequence = 0x5678,
            Data = new byte[] { 1, 2, 3, 4 }
        };

        var bytes = packet.Serialize();

        bytes.Length.Should().Be(12);
        bytes[0].Should().Be(8);
        bytes[1].Should().Be(0);

        ushort check = IcmpPacket.ComputeChecksum(bytes);
        check.Should().Be(0);
    }
    [Theory]
    [InlineData("192.168.1.5", "192.168.1.5", true)]
    [InlineData("192.168.1.5", "192.168.1.0/24", true)]
    [InlineData("192.168.1.5", "192.168.1.1-192.168.1.10", true)]
    [InlineData("192.168.1.5", "10.0.0.1, 192.168.1.5, 172.16.0.0/16", true)]
    [InlineData("192.168.1.5", "192.168.2.0/24", false)]
    [InlineData("192.168.1.5", "192.168.1.10-192.168.1.20", false)]
    [InlineData("192.168.1.5", "", true)]
    [InlineData("fe80::5", "fe80::/64", true)]
    [InlineData("fe80::5", "fe80::1-fe80::10", true)]
    [InlineData("fe80::5", "fe81::/64", false)]
    public void IsIpInRanges_Should_Match_Correctly(string ip, string ranges, bool expected)
    {
        var result = NetworkScannerUtils.IsIpInRanges(ip, ranges);
        result.Should().Be(expected);
    }
}
