using System.Collections.Generic;
using FluentAssertions;
using Xunit;
using NetworkScanner.Core;

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
}
