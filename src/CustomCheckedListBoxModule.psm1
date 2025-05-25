class CustomCheckedListBox : System.Windows.Forms.CheckedListBox {
    
    static [System.Collections.Hashtable] $logos = [System.Collections.Hashtable]::new()
    
    CustomCheckedListBox() {
        $this.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawVariable
        $this.Font = New-Object System.Drawing.Font('Segoe UI', 10.5)  
        $this.Invalidate()
    }

    [void] OnDrawItem([System.Windows.Forms.DrawItemEventArgs] $e) {
        $e.DrawBackground()

        $item = $this.Items[$e.Index]
        $logoPath = [CustomCheckedListBox]::logos[$item]

        if ([string]::IsNullOrEmpty($logoPath)) {
            $e.DrawFocusRectangle()
            return
        }

        if (-not [System.IO.File]::Exists($logoPath)) {
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

        $resizedImage = New-Object System.Drawing.Bitmap($originalImage, 30, 30)

        $checkboxSize = 20
        $checkboxPadding = 5  
        $imagePadding = 5     
        $imageOffset = $checkboxSize + $checkboxPadding
        $textOffset = $imageOffset + $resizedImage.Width + $imagePadding
        
        $checkboxBounds = New-Object System.Drawing.Rectangle($e.Bounds.Location.X, ($e.Bounds.Location.Y + (($this.ItemHeight - $checkboxSize) / 2) + 3), $checkboxSize, $checkboxSize)
        $checkedState = if ($this.GetItemChecked($e.Index)) { [System.Windows.Forms.VisualStyles.CheckBoxState]::CheckedNormal } else { [System.Windows.Forms.VisualStyles.CheckBoxState]::UncheckedNormal }
        [System.Windows.Forms.CheckBoxRenderer]::DrawCheckBox($e.Graphics, $checkboxBounds.Location, $checkedState)

        $e.Graphics.DrawImage($resizedImage, $e.Bounds.Location.X + $imageOffset, $e.Bounds.Location.Y + ($this.ItemHeight - $resizedImage.Height) / 2)
       
        $e.Graphics.DrawString($item.ToString(), $this.Font, [System.Drawing.Brushes]::White, $e.Bounds.Location.X + $textOffset, $e.Bounds.Location.Y + ($this.ItemHeight - $this.Font.Height) / 2)

        $e.DrawFocusRectangle()
    }

    #  [void] OnMeasureItem([System.Windows.Forms.MeasureItemEventArgs] $e) {
    #      $fontHeight = $this.Font.Height  
    #      $checkboxSize = 20
    #      $imageHeight = 30
    #      $minHeight = [Math]::Max($fontHeight, [Math]::Max($checkboxSize, $imageHeight))
    #      
    #      # Add the configurable vertical padding to increase spacing between items
    #      $e.ItemHeight = $minHeight + $this.ItemVerticalPadding
    #  }
    
}