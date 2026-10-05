param(
    [Parameter(Mandatory=$true)][string]$ImagePath,
    [int]$Width = 150,
    [int]$Threshold = 140,
    [string]$Rotate = "0"
)
# 把图片降采样成 ASCII 网格输出，便于在终端直接阅读验证码/图像内容
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$src0 = [System.Drawing.Image]::FromFile($ImagePath)
$src = $src0
try {
    if ($Rotate -eq "90") { $src0.RotateFlip([System.Drawing.RotateFlipType]::Rotate90FlipNone) }
    elseif ($Rotate -eq "270") { $src0.RotateFlip([System.Drawing.RotateFlipType]::Rotate270FlipNone) }
    $ratio = $Width / $src.Width
    $h = [int][Math]::Floor($src.Height * $ratio)
    $bmp = New-Object System.Drawing.Bitmap($Width, $h)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.DrawImage($src, 0, 0, $Width, $h)
    $g.Dispose()
    $lines = @()
    for ($y = 0; $y -lt $h; $y += 1) {
        $row = ''
        for ($x = 0; $x -lt $Width; $x++) {
            $c = $bmp.GetPixel($x, $y)
            $gray = [int](0.299 * $c.R + 0.587 * $c.G + 0.114 * $c.B)
            if ($gray -lt $Threshold) { $row += '#' } else { $row += ' ' }
        }
        $lines += $row
    }
    $lines | ForEach-Object { Write-Output $_ }
}
finally {
    $src.Dispose()
}
