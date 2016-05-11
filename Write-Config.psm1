function Write-Config {
<#

/#>



    param
    (
        [parameter(Mandatory=$false,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true
        )]
        [string]$PrefixString="Interface",
        [string]$OutFile
    )
    




[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

$listForm               = New-Object System.Windows.Forms.Form 
$listForm.Text          = "Item/Interface List"
$listForm.Size          = New-Object System.Drawing.Size(300,340) 
$listForm.StartPosition = "CenterScreen"

$listForm.KeyPreview    = $True
$listForm.Add_KeyDown({if ($_.KeyCode -eq "Escape")    {$listForm.Close()}})

$listOKButton           = New-Object System.Windows.Forms.Button
$listOKButton.Location  = New-Object System.Drawing.Size(75,280)
$listOKButton.Size      = New-Object System.Drawing.Size(75,23)
$listOKButton.Text      = "OK"
$listOKButton.Add_Click({$list=$listTextBox.Text;$listForm.Close()})
$listForm.Controls.Add($listOKButton)

$listCancelButton           = New-Object System.Windows.Forms.Button
$listCancelButton.Location  = New-Object System.Drawing.Size(150,280)
$listCancelButton.Size      = New-Object System.Drawing.Size(75,23)
$listCancelButton.Text      = "Cancel"
$listCancelButton.Add_Click({$listForm.Close()})
$listForm.Controls.Add($listCancelButton)

$listObjLabel           = New-Object System.Windows.Forms.Label
$listObjLabel.Location  = New-Object System.Drawing.Size(10,20) 
$listObjLabel.Size      = New-Object System.Drawing.Size(280,20) 
$listObjLabel.Text      = "Enter list of interfaces or items below:"
$listForm.Controls.Add($listObjLabel) 

$listTextBox            = New-Object System.Windows.Forms.TextBox 
$listTextBox.Location   = New-Object System.Drawing.Size(10,40) 
$listTextBox.Size       = New-Object System.Drawing.Size(260,220) 
$listTextBox.Multiline  = $true
$listForm.Controls.Add($listTextBox)

$listForm.Topmost = $True

$listForm.Add_Shown({$listForm.Activate()})
[void] $listForm.ShowDialog()

$configForm                 = New-Object System.Windows.Forms.Form 
$configForm.Text            = "Config Statements"
$configForm.Size            = New-Object System.Drawing.Size(300,340) 
$configForm.StartPosition   = "CenterScreen"

$configForm.KeyPreview = $True
$configForm.Add_KeyDown({if ($_.KeyCode -eq "Escape")    {$configForm.Close()}})

$configOKButton             = New-Object System.Windows.Forms.Button
$configOKButton.Location    = New-Object System.Drawing.Size(75,280)
$configOKButton.Size        = New-Object System.Drawing.Size(75,23)
$configOKButton.Text        = "OK"
$configOKButton.Add_Click({$config=$configTextBox.Text;$configForm.Close()})
$configForm.Controls.Add($configOKButton)

$configCancelButton             = New-Object System.Windows.Forms.Button
$configCancelButton.Location    = New-Object System.Drawing.Size(150,280)
$configCancelButton.Size        = New-Object System.Drawing.Size(75,23)
$configCancelButton.Text        = "Cancel"
$configCancelButton.Add_Click({$configForm.Close()})
$configForm.Controls.Add($configCancelButton)

$configObjLabel             = New-Object System.Windows.Forms.Label
$configObjLabel.Location    = New-Object System.Drawing.Size(10,20) 
$configObjLabel.Size        = New-Object System.Drawing.Size(280,20) 
$configObjLabel.Text        = "Enter Configuration Statements:"
$configForm.Controls.Add($configObjLabel) 

$configTextBox              = New-Object System.Windows.Forms.TextBox 
$configTextBox.Location     = New-Object System.Drawing.Size(10,40) 
$configTextBox.Size         = New-Object System.Drawing.Size(260,220) 
$configTextBox.Multiline    = $true
$configForm.Controls.Add($configTextBox)

$configForm.Topmost = $True

$configForm.Add_Shown({$configForm.Activate()})
[void] $configForm.ShowDialog()

$config = $config   -split "`n"
$list   = $list     -split "`n"

$list | foreach {
        "$PrefixString $_ "
        $config 
        "!"
        }
}
