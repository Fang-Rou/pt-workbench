param(
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [int]$Scale = 5,
    [int]$DarkThreshold = 130,
    [int]$SatMax = 45
)
# 验证码去噪: 放大 -> 只保留低饱和(灰/黑)像素(彩色噪声线剔除) -> 二值化 -> PNG
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$src = [System.Drawing.Image]::FromFile($ImagePath)
try {
    $w = $src.Width * $Scale
    $h = $src.Height * $Scale
    $bmp = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($src, 0, 0, $w, $h)
    $g.Dispose()
    for ($x = 0; $x -lt $w; $x++) {
        for ($y = 0; $y -lt $h; $y++) {
            $c = $bmp.GetPixel($x, $y)
            $mx = [Math]::Max($c.R, [Math]::Max($c.G, $c.B))
            $mn = [Math]::Min($c.R, [Math]::Min($c.G, $c.B))
            $sat = $mx - $mn
            if ($sat -le $SatMax) {
                $gray = [int](0.299 * $c.R + 0.587 * $c.G + 0.114 * $c.B)
                if ($gray -lt $DarkThreshold) { $bmp.SetPixel($x, $y, [System.Drawing.Color]::Black) }
                else { $bmp.SetPixel($x, $y, [System.Drawing.Color]::White) }
            } else {
                $bmp.SetPixel($x, $y, [System.Drawing.Color]::White)
            }
        }
    }
    $bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Output ("CLEAN_OK " + $w + "x" + $h)
}
finally {
    $src.Dispose()
}
