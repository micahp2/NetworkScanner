Add-Type -AssemblyName System.Drawing

$pngPath = "C:\Users\Micah\.gemini\antigravity\brain\084682db-7a4d-4d3b-b108-a3ef55cceffe\app_icon_v3_1780425320577.png"
$wpfDest = "c:\Users\Micah\OneDrive\Documents\GitHub\NetworkScanner\Assets\app_icon.ico"
$winuiDest = "c:\Users\Micah\OneDrive\Documents\GitHub\NetworkScanner\NetworkScanner.WinUIPrototype\Assets\app_icon.ico"

# Create directories if they do not exist
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($wpfDest))
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($winuiDest))

# Load image
$img = [System.Drawing.Image]::FromFile($pngPath)

# Resize to 256x256 with transparency color key
$bmp = New-Object System.Drawing.Bitmap(256, 256)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

$attr = New-Object System.Drawing.Imaging.ImageAttributes
# Key out black background (from 0,0,0 to 18,18,18)
$lowColor = [System.Drawing.Color]::FromArgb(0, 0, 0)
$highColor = [System.Drawing.Color]::FromArgb(18, 18, 18)
$attr.SetColorKey($lowColor, $highColor)

$destRect = New-Object System.Drawing.Rectangle(0, 0, 256, 256)
$g.DrawImage($img, $destRect, 0, 0, $img.Width, $img.Height, [System.Drawing.GraphicsUnit]::Pixel, $attr)
$g.Dispose()

# Save to memory stream as PNG
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $ms.ToArray()
$ms.Dispose()
$bmp.Dispose()
$img.Dispose()

# Write function for ICO writing
function Write-IcoFile($destPath, $bytes) {
    $icoStream = [System.IO.File]::Create($destPath)
    
    # Icon Header
    $icoStream.WriteByte(0) # Reserved
    $icoStream.WriteByte(0)
    $icoStream.WriteByte(1) # Type (1 = Icon)
    $icoStream.WriteByte(0)
    $icoStream.WriteByte(1) # Image Count (1)
    $icoStream.WriteByte(0)

    # Directory Entry
    $icoStream.WriteByte(0) # Width (0 = 256)
    $icoStream.WriteByte(0) # Height (0 = 256)
    $icoStream.WriteByte(0) # Color count
    $icoStream.WriteByte(0) # Reserved
    $icoStream.WriteByte(1) # Planes (1)
    $icoStream.WriteByte(0)
    $icoStream.WriteByte(32) # Bits per pixel (32)
    $icoStream.WriteByte(0)

    # PNG size (4 bytes, little-endian)
    $pngSize = $bytes.Length
    $icoStream.WriteByte([byte]($pngSize -band 0xFF))
    $icoStream.WriteByte([byte](($pngSize -shr 8) -band 0xFF))
    $icoStream.WriteByte([byte](($pngSize -shr 16) -band 0xFF))
    $icoStream.WriteByte([byte](($pngSize -shr 24) -band 0xFF))

    # Offset of PNG data (22, 4 bytes, little-endian)
    $icoStream.WriteByte(22)
    $icoStream.WriteByte(0)
    $icoStream.WriteByte(0)
    $icoStream.WriteByte(0)

    # Write PNG bytes
    $icoStream.Write($bytes, 0, $bytes.Length)
    $icoStream.Close()
}

Write-IcoFile $wpfDest $pngBytes
Write-IcoFile $winuiDest $pngBytes

Write-Host "Icons generated successfully at:"
Write-Host "  $wpfDest"
Write-Host "  $winuiDest"
