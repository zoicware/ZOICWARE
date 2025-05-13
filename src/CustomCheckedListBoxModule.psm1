class CustomCheckedListBox : System.Windows.Forms.CheckedListBox {
    
    static [System.Collections.Hashtable] $logos = [System.Collections.Hashtable]::new()

    CustomCheckedListBox() {
        $this.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawVariable
    }

    [void] OnDrawItem([System.Windows.Forms.DrawItemEventArgs] $e) {
        $e.DrawBackground()

        $item = $this.Items[$e.Index]
        $logoPath = [CustomCheckedListBox]::logos[$item]

        if ([string]::IsNullOrEmpty($logoPath)) {
            #  Write-Host "Logo path for item '$item' is null or empty."
            $e.DrawFocusRectangle()
            return
        }

        if (-not [System.IO.File]::Exists($logoPath)) {
            #  Write-Host "Logo path '$logoPath' does not exist."
            $e.DrawFocusRectangle()
            return
        }

        try {
            $originalImage = [System.Drawing.Image]::FromFile($logoPath)
        }
        catch {
            Write-Host "Failed to load image from path '$logoPath'. Error: $_"
            $e.DrawFocusRectangle()
            return
        }

        $resizedImage = New-Object System.Drawing.Bitmap($originalImage, 20, 20)

        $checkboxSize = 20
        $imageOffset = $checkboxSize   
        $textOffset = $imageOffset + $resizedImage.Width + 5  
    
        $checkboxBounds = New-Object System.Drawing.Rectangle($e.Bounds.Location.X , ($e.Bounds.Location.Y + (($this.ItemHeight - $checkboxSize) + 6)), $checkboxSize, $checkboxSize)
        $checkedState = if ($this.GetItemChecked($e.Index)) { [System.Windows.Forms.VisualStyles.CheckBoxState]::CheckedNormal } else { [System.Windows.Forms.VisualStyles.CheckBoxState]::UncheckedNormal }
        [System.Windows.Forms.CheckBoxRenderer]::DrawCheckBox($e.Graphics, $checkboxBounds.Location, $checkedState)

        $e.Graphics.DrawImage($resizedImage, $e.Bounds.Location.X + $imageOffset, $e.Bounds.Location.Y + ($this.ItemHeight - $resizedImage.Height) / 2)
        $e.Graphics.DrawString($item.ToString(), $e.Font, [System.Drawing.Brushes]::White, $e.Bounds.Location.X + $textOffset, $e.Bounds.Location.Y + ($this.ItemHeight - $e.Font.Height) / 2)

        $e.DrawFocusRectangle()
    }

    [void] OnMeasureItem([System.Windows.Forms.MeasureItemEventArgs] $e) {
        $e.ItemHeight = 40
    }

}
