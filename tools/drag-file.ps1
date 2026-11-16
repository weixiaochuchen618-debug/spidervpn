# 真拖放源（由 Python 驱动鼠标）：
#   1) 脚本自己建一个小窗口并打印 READY；
#   2) 外部在窗口上按下左键 → 触发 DoDragDrop，脚本打印 STARTED；
#   3) 外部把光标移到目标点并松手 → 脚本打印 EFFECT 并退出。
# 鼠标动作放在外部：DoDragDrop 是模态循环，脚本内部用 Timer 松手会卡住。
param(
  [Parameter(Mandatory = $true)][string]$Path,
  [int]$HoldSeconds = 25
)
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.ShowInTaskbar = $false
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(2, 2)
$form.Size = New-Object System.Drawing.Size(220, 120)
$form.TopMost = $true
$label = New-Object System.Windows.Forms.Label
$label.Text = 'DRAG SOURCE'
$label.Dock = 'Fill'
$label.TextAlign = 'MiddleCenter'
$form.Controls.Add($label)

$script:effect = 'none'
$form.add_Shown({ [Console]::Out.WriteLine('READY'); [Console]::Out.Flush() })
$label.add_MouseDown({
  [Console]::Out.WriteLine('STARTED'); [Console]::Out.Flush()
  $data = New-Object System.Windows.Forms.DataObject
  $data.SetData([System.Windows.Forms.DataFormats]::FileDrop, [string[]]@($Path))
  $script:effect = [string]$label.DoDragDrop($data, [System.Windows.Forms.DragDropEffects]::Copy)
  [Console]::Out.WriteLine("EFFECT=$($script:effect)"); [Console]::Out.Flush()
  $form.Close()
})

$watchdog = New-Object System.Windows.Forms.Timer
$watchdog.Interval = ($HoldSeconds * 1000)
$watchdog.add_Tick({ [Console]::Out.WriteLine('WATCHDOG'); $form.Close() })
$watchdog.Start()

[System.Windows.Forms.Application]::Run($form)
Write-Output ("effect={0}" -f $script:effect)
