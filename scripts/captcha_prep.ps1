param(
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [int]$Scale = 4,
    [int]$Threshold = 150
)
# 验证码预处理: 放大 -> 灰度 -> 二值化，输出 PNG 供 Windows OCR
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
    # 灰度 + 二值化
    for ($x = 0; $x -lt $w; $x++) {
        for ($y = 0; $y -lt $h; $y++) {
            $c = $bmp.GetPixel($x, $y)
            $gray = [int](0.299 * $c.R + 0.587 * $c.G + 0.114 * $c.B)
            $val = if ($gray -gt $Threshold) { 255 } else { 0 }
            $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(255, $val, $val, $val))
        }
    }
    $bmp.Save($OutPath, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Output ("PREP_OK " + $w + "x" + $h)
}
finally {
    $src.Dispose()
}
