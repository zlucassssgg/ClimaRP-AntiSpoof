-- server.lua
ESX = exports["es_extended"]:getSharedObject()

-- Configuración
local Config = {
    DiscordWebhook = "TU_WEBHOOK_URL_AQUI", -- Webhook de Discord
    CheckTimeHours = 24, -- Horas para verificar conexiones anteriores
    DatabaseName = "antispoof_logs", -- Nombre de la tabla en la base de datos
    RequiredIdentifiers = {"discord", "steam", "license"}, -- Identificadores requeridos
    EnableRockstarCheck = true, -- Si verificar Rockstar Social Club
    
    -- Permisos para comandos
    CommandPermissions = {
        checkip = {"owner", "admin", "superadmin"}, -- Grupos que pueden usar /checkip
        suspicious = {"owner", "admin", "superadmin"},
        whitelist = {"owner", "admin", "superadmin"}, -- Grupos que pueden usar /suspicious
        notifications = {"admin", "owner"} -- Grupos que reciben notificaciones en el chat
    }
}

-- Variables globales
local PlayerConnections = {}
local SuspiciousIPs = {}

-- Crear tabla en la base de datos
MySQL.ready(function()
    MySQL.Async.execute([[
        CREATE TABLE IF NOT EXISTS antispoof_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            steam_id VARCHAR(50),
            discord_id VARCHAR(50),
            license_id VARCHAR(50),
            rockstar_id VARCHAR(50),
            player_name VARCHAR(100),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_suspicious BOOLEAN DEFAULT FALSE
        )
    ]], {})
    
    MySQL.Async.execute([[
        CREATE TABLE IF NOT EXISTS suspicious_reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            reason TEXT NOT NULL,
            connections_data TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action_taken VARCHAR(100) DEFAULT 'logged'
        )
    ]], {})
    
    MySQL.Async.execute([[
        CREATE TABLE IF NOT EXISTS ip_whitelist (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            added_by VARCHAR(100),
            reason VARCHAR(255),
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ]], {})
    
    print("^2[ANTI-SPOOF]^0 Base de datos inicializada correctamente")
end)

-- Función para verificar permisos
function HasPermission(xPlayer, commandType)
    local playerGroup = xPlayer.getGroup()
    local allowedGroups = Config.CommandPermissions[commandType] or {}
    
    for _, group in pairs(allowedGroups) do
        if playerGroup == group then
            return true
        end
    end
    return false
end
-- Función para obtener identificadores del jugador
function GetPlayerIdentifiers(source)
    local identifiers = {
        steam = nil,
        discord = nil,
        license = nil,
        rockstar = nil,
        ip = nil
    }
    
    for i = 0, GetNumPlayerIdentifiers(source) - 1 do
        local id = GetPlayerIdentifier(source, i)
        
        if string.match(id, "steam:") then
            identifiers.steam = id
        elseif string.match(id, "discord:") then
            identifiers.discord = id
        elseif string.match(id, "license:") then
            identifiers.license = id
        elseif string.match(id, "live:") then
            identifiers.rockstar = id
        elseif string.match(id, "ip:") then
            identifiers.ip = string.gsub(id, "ip:", "")
        end
    end
    
    return identifiers
end

-- Función para enviar mensaje a Discord
function SendDiscordLog(title, description, color, fields)
    local embed = {
        {
            ["title"] = title,
            ["description"] = description,
            ["type"] = "rich",
            ["color"] = color or 15158332, -- Rojo por defecto
            ["fields"] = fields or {},
            ["timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            ["footer"] = {
                ["text"] = "Anti-Spoof System | " .. GetConvar("sv_hostname", "FiveM Server")
            }
        }
    }
    
    PerformHttpRequest(Config.DiscordWebhook, function(err, text, headers) 
        if err ~= 200 then
            print("^1[ANTI-SPOOF ERROR]^0 Error enviando a Discord: " .. err)
        end
    end, 'POST', json.encode({embeds = embed}), { ['Content-Type'] = 'application/json' })
end

-- Función para verificar si hay actividad sospechosa
function CheckSuspiciousActivity(playerData)
    local ip = playerData.ip
    
    -- Verificar si la IP está en whitelist antes de proceder
    MySQL.Async.fetchScalar('SELECT COUNT(*) FROM ip_whitelist WHERE ip_address = @ip', {
        ['@ip'] = ip
    }, function(whitelistCount)
        if whitelistCount and whitelistCount > 0 then
            print("^3[ANTI-SPOOF]^0 IP " .. ip .. " está en whitelist, saltando verificación")
            return
        end
        
        local timeCheck = os.time() - (Config.CheckTimeHours * 3600) -- Convertir horas a segundos
        local timeCheckStr = os.date("%Y-%m-%d %H:%M:%S", timeCheck)
        
        MySQL.Async.fetchAll('SELECT * FROM antispoof_logs WHERE ip_address = @ip AND timestamp > @timecheck ORDER BY timestamp DESC', {
            ['@ip'] = ip,
            ['@timecheck'] = timeCheckStr
        }, function(results)
            if #results > 0 then
                local suspiciousReasons = {}
                local uniqueSteam = {}
                local uniqueDiscord = {}
                local uniqueLicense = {}
                local uniqueRockstar = {}
                local uniqueNames = {}
                
                -- Agregar la conexión actual para análisis
                table.insert(results, 1, playerData)
                
                -- Analizar todas las conexiones
                for _, connection in pairs(results) do
                    if connection.steam_id and connection.steam_id ~= "" then
                        uniqueSteam[connection.steam_id] = true
                    end
                    if connection.discord_id and connection.discord_id ~= "" then
                        uniqueDiscord[connection.discord_id] = true
                    end
                    if connection.license_id and connection.license_id ~= "" then
                        uniqueLicense[connection.license_id] = true
                    end
                    if connection.rockstar_id and connection.rockstar_id ~= "" then
                        uniqueRockstar[connection.rockstar_id] = true
                    end
                    if connection.player_name and connection.player_name ~= "" then
                        uniqueNames[connection.player_name] = true
                    end
                end
                
                -- Contar identificadores únicos
                local steamCount = 0
                local discordCount = 0
                local licenseCount = 0
                local rockstarCount = 0
                local nameCount = 0
                
                for _ in pairs(uniqueSteam) do steamCount = steamCount + 1 end
                for _ in pairs(uniqueDiscord) do discordCount = discordCount + 1 end
                for _ in pairs(uniqueLicense) do licenseCount = licenseCount + 1 end
                for _ in pairs(uniqueRockstar) do rockstarCount = rockstarCount + 1 end
                for _ in pairs(uniqueNames) do nameCount = nameCount + 1 end
                
                -- Detectar múltiples cuentas
                if steamCount > 1 then
                    table.insert(suspiciousReasons, "Múltiples cuentas Steam (" .. steamCount .. ")")
                end
                if discordCount > 1 then
                    table.insert(suspiciousReasons, "Múltiples cuentas Discord (" .. discordCount .. ")")
                end
                if licenseCount > 1 then
                    table.insert(suspiciousReasons, "Múltiples licencias (" .. licenseCount .. ")")
                end
                if rockstarCount > 1 and Config.EnableRockstarCheck then
                    table.insert(suspiciousReasons, "Múltiples cuentas Rockstar (" .. rockstarCount .. ")")
                end
                if nameCount > 1 then
                    table.insert(suspiciousReasons, "Múltiples nombres (" .. nameCount .. ")")
                end
                
                -- Si hay razones sospechosas, reportar
                if #suspiciousReasons > 0 then
                    ReportSuspiciousActivity(ip, suspiciousReasons, results, playerData.source)
                end
            end
        end)
    end)
end

-- Función para reportar actividad sospechosa
function ReportSuspiciousActivity(ip, reasons, connections, playerSource)
    local reasonStr = table.concat(reasons, ", ")
    local connectionsJson = json.encode(connections)
    
    -- Guardar en base de datos
    MySQL.Async.execute('INSERT INTO suspicious_reports (ip_address, reason, connections_data) VALUES (@ip, @reason, @connections)', {
        ['@ip'] = ip,
        ['@reason'] = reasonStr,
        ['@connections'] = connectionsJson
    })
    
    -- Marcar como sospechoso en la tabla principal
    MySQL.Async.execute('UPDATE antispoof_logs SET is_suspicious = 1 WHERE ip_address = @ip AND timestamp >= @timecheck', {
        ['@ip'] = ip,
        ['@timecheck'] = os.date("%Y-%m-%d %H:%M:%S", os.time() - (Config.CheckTimeHours * 3600))
    })
    
    -- También marcar la conexión actual como sospechosa si existe
    if playerSource then
        MySQL.Async.execute([[
            UPDATE antispoof_logs 
            SET is_suspicious = 1 
            WHERE ip_address = @ip 
            AND player_name = @name 
            ORDER BY timestamp DESC 
            LIMIT 1
        ]], {
            ['@ip'] = ip,
            ['@name'] = GetPlayerName(playerSource)
        })
    end
    
    -- Preparar campos para Discord
    local fields = {
        {
            ["name"] = "🚨 IP Sospechosa",
            ["value"] = "```" .. ip .. "```",
            ["inline"] = true
        },
        {
            ["name"] = "📊 Razones de Sospecha",
            ["value"] = table.concat(reasons, "\n• "),
            ["inline"] = false
        }
    }
    
    -- Agregar detalles de conexiones recientes
    local connectionDetails = {}
    for i = 1, math.min(5, #connections) do
        local conn = connections[i]
        local detail = "**" .. (conn.player_name or "Desconocido") .. "**"
        if conn.steam_id then detail = detail .. "\n🎮 Steam: " .. string.gsub(conn.steam_id, "steam:", "") end
        if conn.discord_id then detail = detail .. "\n💬 Discord: <@" .. string.gsub(conn.discord_id, "discord:", "") .. ">" end
        if conn.license_id then detail = detail .. "\n🆔 License: " .. string.sub(conn.license_id, 1, 20) .. "..." end
        table.insert(connectionDetails, detail)
    end
    
    if #connectionDetails > 0 then
        table.insert(fields, {
            ["name"] = "🔍 Últimas Conexiones",
            ["value"] = table.concat(connectionDetails, "\n\n"),
            ["inline"] = false
        })
    end
    
    -- Información del jugador actual
    if playerSource then
        table.insert(fields, {
            ["name"] = "👤 Jugador Actual",
            ["value"] = "ID: " .. playerSource .. "\nNombre: " .. GetPlayerName(playerSource),
            ["inline"] = true
        })
    end
    
    -- Enviar a Discord
    SendDiscordLog(
        "🚨 POSIBLE SPOOFING DETECTADO",
        "Se detectó actividad sospechosa desde la IP **" .. ip .. "**",
        15158332, -- Rojo
        fields
    )
    
    -- Notificar a admins online
    local xPlayers = ESX.GetPlayers()
    for i = 1, #xPlayers do
        local xPlayer = ESX.GetPlayerFromId(xPlayers[i])
        if xPlayer then
            local playerGroup = xPlayer.getGroup()
            local allowedGroups = Config.CommandPermissions.notifications or {"admin", "superadmin"}
            
            for _, group in pairs(allowedGroups) do
                if playerGroup == group then
                    TriggerClientEvent('chat:addMessage', xPlayer.source, {
                        color = {255, 0, 0},
                        multiline = true,
                        args = {"[ANTI-SPOOF]", "Actividad sospechosa detectada desde IP: " .. ip .. " - Razón: " .. reasonStr}
                    })
                    break
                end
            end
        end
    end
    
    print("^1[ANTI-SPOOF]^0 Actividad sospechosa detectada desde IP: " .. ip .. " - Razones: " .. reasonStr)
end

-- Función para registrar conexión
function LogPlayerConnection(source)
    local identifiers = GetPlayerIdentifiers(source)
    local playerName = GetPlayerName(source)
    
    if not identifiers.ip then
        print("^1[ANTI-SPOOF ERROR]^0 No se pudo obtener la IP del jugador: " .. source)
        return
    end
    
    -- Verificar si la IP ya tiene reportes sospechosos
    MySQL.Async.fetchScalar('SELECT COUNT(*) FROM suspicious_reports WHERE ip_address = @ip', {
        ['@ip'] = identifiers.ip
    }, function(suspiciousCount)
        local isSuspicious = (suspiciousCount and suspiciousCount > 0) and 1 or 0
        
        local connectionData = {
            ip = identifiers.ip,
            steam_id = identifiers.steam,
            discord_id = identifiers.discord,
            license_id = identifiers.license,
            rockstar_id = identifiers.rockstar,
            player_name = playerName,
            source = source,
            timestamp = os.date("%Y-%m-%d %H:%M:%S"),
            is_suspicious = isSuspicious
        }
        
        -- Guardar en base de datos
        MySQL.Async.execute([[
            INSERT INTO antispoof_logs (ip_address, steam_id, discord_id, license_id, rockstar_id, player_name, is_suspicious) 
            VALUES (@ip, @steam, @discord, @license, @rockstar, @name, @suspicious)
        ]], {
            ['@ip'] = connectionData.ip,
            ['@steam'] = connectionData.steam_id,
            ['@discord'] = connectionData.discord_id,
            ['@license'] = connectionData.license_id,
            ['@rockstar'] = connectionData.rockstar_id,
            ['@name'] = connectionData.player_name,
            ['@suspicious'] = connectionData.is_suspicious
        })
        
        -- Verificar actividad sospechosa
        CheckSuspiciousActivity(connectionData)
        
        -- Almacenar en memoria para acceso rápido
        PlayerConnections[source] = connectionData
        
        local suspiciousText = isSuspicious == 1 and " [SOSPECHOSA]" or ""
        print("^2[ANTI-SPOOF]^0 Conexión registrada: " .. playerName .. " desde IP: " .. identifiers.ip .. suspiciousText)
    end)
end

-- Eventos
AddEventHandler('playerConnecting', function(name, setKickReason, deferrals)
    local source = source
    deferrals.defer()
    
    -- Esperar un momento para que se carguen los identificadores
    Wait(1000)
    
    -- Registrar la conexión
    LogPlayerConnection(source)
    
    deferrals.done()
end)

AddEventHandler('playerDropped', function(reason)
    local source = source
    if PlayerConnections[source] then
        print("^3[ANTI-SPOOF]^0 Jugador desconectado: " .. GetPlayerName(source) .. " (IP: " .. PlayerConnections[source].ip .. ")")
        PlayerConnections[source] = nil
    end
end)

-- Comandos para administradores
ESX.RegisterCommand('checkip', Config.CommandPermissions.checkip, function(xPlayer, args, showError)
    if args.ip then
        MySQL.Async.fetchAll('SELECT * FROM antispoof_logs WHERE ip_address = @ip ORDER BY timestamp DESC LIMIT 10', {
            ['@ip'] = args.ip
        }, function(results)
            if #results > 0 then
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {0, 255, 255},
                    args = {"[ANTI-SPOOF]", "Conexiones encontradas para IP " .. args.ip .. ":"}
                })
                
                for i, result in ipairs(results) do
                    TriggerClientEvent('chat:addMessage', xPlayer.source, {
                        color = {255, 255, 255},
                        args = {"", string.format("%d. %s | %s | Steam: %s", 
                            i, 
                            result.player_name or "N/A", 
                            result.timestamp, 
                            result.steam_id and string.gsub(result.steam_id, "steam:", "") or "N/A"
                        )}
                    })
                end
            else
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 0, 0},
                    args = {"[ANTI-SPOOF]", "No se encontraron conexiones para la IP: " .. args.ip}
                })
            end
        end)
    else
        showError("Uso: /checkip [ip]")
    end
end, true, {help = "Verificar historial de una IP", validate = true, arguments = {
    {name = 'ip', help = 'Dirección IP a verificar', type = 'string'}
}})

ESX.RegisterCommand('suspicious', Config.CommandPermissions.suspicious, function(xPlayer, args, showError)
    MySQL.Async.fetchAll('SELECT * FROM suspicious_reports ORDER BY timestamp DESC LIMIT 10', {}, function(results)
        if #results > 0 then
            TriggerClientEvent('chat:addMessage', xPlayer.source, {
                color = {255, 165, 0},
                args = {"[ANTI-SPOOF]", "Últimos reportes sospechosos:"}
            })
            
            for i, result in ipairs(results) do
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 255, 255},
                    args = {"", string.format("%d. IP: %s | %s | %s", 
                        i, 
                        result.ip_address, 
                        result.timestamp, 
                        string.sub(result.reason, 1, 50) .. "..."
                    )}
                })
            end
        else
            TriggerClientEvent('chat:addMessage', xPlayer.source, {
                color = {0, 255, 0},
                args = {"[ANTI-SPOOF]", "No hay reportes sospechosos recientes"}
            })
        end
    end)
end, true, {help = "Ver actividad sospechosa reciente"})

-- Comando para agregar IP a whitelist
ESX.RegisterCommand('whitelistip', Config.CommandPermissions.whitelist, function(xPlayer, args, showError)
    
    if args.ip then
        local reason = args.reason or "Sin razón especificada"
        local adminName = GetPlayerName(xPlayer.source)
        
        -- Verificar si ya está en whitelist
        MySQL.Async.fetchScalar('SELECT COUNT(*) FROM ip_whitelist WHERE ip_address = @ip', {
            ['@ip'] = args.ip
        }, function(count)
            if count and count > 0 then
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 165, 0},
                    args = {"[ANTI-SPOOF]", "La IP " .. args.ip .. " ya está en la whitelist"}
                })
                return
            end
            
            -- Agregar a whitelist
            MySQL.Async.execute('INSERT INTO ip_whitelist (ip_address, added_by, reason) VALUES (@ip, @admin, @reason)', {
                ['@ip'] = args.ip,
                ['@admin'] = adminName,
                ['@reason'] = reason
            }, function(insertId)
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {0, 255, 0},
                    args = {"[ANTI-SPOOF]", "IP " .. args.ip .. " agregada a la whitelist correctamente"}
                })
                
                -- Marcar conexiones existentes como no sospechosas
                MySQL.Async.execute('UPDATE antispoof_logs SET is_suspicious = 0 WHERE ip_address = @ip', {
                    ['@ip'] = args.ip
                }, function(affectedRows)
                    if affectedRows > 0 then
                        TriggerClientEvent('chat:addMessage', xPlayer.source, {
                            color = {0, 255, 255},
                            args = {"[ANTI-SPOOF]", "Se actualizaron " .. affectedRows .. " conexiones previas como no sospechosas"}
                        })
                    end
                end)
                
                -- Log a Discord
                SendDiscordLog(
                    "✅ IP AGREGADA A WHITELIST",
                    "Una IP ha sido agregada a la lista blanca",
                    65280, -- Verde
                    {
                        {
                            ["name"] = "🌐 IP Agregada",
                            ["value"] = "```" .. args.ip .. "```",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "👤 Agregada por",
                            ["value"] = adminName .. " (ID: " .. xPlayer.source .. ")",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "📝 Razón",
                            ["value"] = reason,
                            ["inline"] = false
                        }
                    }
                )
                
                print("^2[ANTI-SPOOF]^0 IP " .. args.ip .. " agregada a whitelist por " .. adminName)
            end)
        end)
    else
        showError("Uso: /whitelistip [ip] [razón opcional]")
    end
end, true, {help = "Agregar IP a la whitelist", validate = true, arguments = {
    {name = 'ip', help = 'Dirección IP a agregar', type = 'string'},
    {name = 'reason', help = 'Razón para agregar (opcional)', type = 'string', optional = true}
}})

-- Comando para quitar IP de whitelist
ESX.RegisterCommand('unwhitelistip', Config.CommandPermissions.whitelist, function(xPlayer, args, showError)
    
    if args.ip then
        -- Verificar si está en whitelist
        MySQL.Async.fetchAll('SELECT * FROM ip_whitelist WHERE ip_address = @ip', {
            ['@ip'] = args.ip
        }, function(results)
            if #results == 0 then
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 165, 0},
                    args = {"[ANTI-SPOOF]", "La IP " .. args.ip .. " no está en la whitelist"}
                })
                return
            end
            
            local whitelistData = results[1]
            local adminName = GetPlayerName(xPlayer.source)
            
            -- Quitar de whitelist
            MySQL.Async.execute('DELETE FROM ip_whitelist WHERE ip_address = @ip', {
                ['@ip'] = args.ip
            }, function(affectedRows)
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 0, 0},
                    args = {"[ANTI-SPOOF]", "IP " .. args.ip .. " removida de la whitelist"}
                })
                
                -- Log a Discord
                SendDiscordLog(
                    "❌ IP REMOVIDA DE WHITELIST",
                    "Una IP ha sido removida de la lista blanca",
                    15158332, -- Rojo
                    {
                        {
                            ["name"] = "🌐 IP Removida",
                            ["value"] = "```" .. args.ip .. "```",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "👤 Removida por",
                            ["value"] = adminName .. " (ID: " .. xPlayer.source .. ")",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "📝 Agregada originalmente por",
                            ["value"] = whitelistData.added_by or "Desconocido",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "📅 Fecha original",
                            ["value"] = whitelistData.timestamp or "Desconocida",
                            ["inline"] = true
                        }
                    }
                )
                
                print("^1[ANTI-SPOOF]^0 IP " .. args.ip .. " removida de whitelist por " .. adminName)
            end)
        end)
    else
        showError("Uso: /unwhitelistip [ip]")
    end
end, true, {help = "Quitar IP de la whitelist", validate = true, arguments = {
    {name = 'ip', help = 'Dirección IP a quitar', type = 'string'}
}})

-- Comando para ver whitelist
ESX.RegisterCommand('viewwhitelist', Config.CommandPermissions.whitelist, function(xPlayer, args, showError)
    
    MySQL.Async.fetchAll('SELECT * FROM ip_whitelist ORDER BY timestamp DESC LIMIT 15', {}, function(results)
        if #results > 0 then
            TriggerClientEvent('chat:addMessage', xPlayer.source, {
                color = {0, 255, 0},
                args = {"[ANTI-SPOOF]", "IPs en Whitelist (" .. #results .. " entradas):"}
            })
            
            for i, result in ipairs(results) do
                TriggerClientEvent('chat:addMessage', xPlayer.source, {
                    color = {255, 255, 255},
                    args = {"", string.format("%d. %s | Por: %s | %s", 
                        i, 
                        result.ip_address,
                        result.added_by or "N/A",
                        result.timestamp or "N/A"
                    )}
                })
            end
        else
            TriggerClientEvent('chat:addMessage', xPlayer.source, {
                color = {255, 165, 0},
                args = {"[ANTI-SPOOF]", "No hay IPs en la whitelist"}
            })
        end
    end)
end, true, {help = "Ver IPs en whitelist"})

-- Comando para marcar/desmarcar IP como sospechosa manualmente
ESX.RegisterCommand('markip', 'user', function(xPlayer, args, showError)
    -- Verificar permisos manualmente
    if not HasPermission(xPlayer, 'checkip') then -- Usa los mismos permisos que checkip
        TriggerClientEvent('chat:addMessage', xPlayer.source, {
            color = {255, 0, 0},
            args = {"[ANTI-SPOOF]", "No tienes permisos para usar este comando"}
        })
        return
    end
    
    if args.ip and args.status then
        local ip = args.ip
        local status = tonumber(args.status)
        
        if status ~= 0 and status ~= 1 then
            showError("Estado debe ser 0 (no sospechosa) o 1 (sospechosa)")
            return
        end
        
        MySQL.Async.execute('UPDATE antispoof_logs SET is_suspicious = @status WHERE ip_address = @ip', {
            ['@ip'] = ip,
            ['@status'] = status
        }, function(affectedRows)
            local statusText = status == 1 and "SOSPECHOSA" or "NO SOSPECHOSA"
            
            TriggerClientEvent('chat:addMessage', xPlayer.source, {
                color = status == 1 and {255, 165, 0} or {0, 255, 0},
                args = {"[ANTI-SPOOF]", "IP " .. ip .. " marcada como " .. statusText .. " (" .. affectedRows .. " registros actualizados)"}
            })
            
            -- Log para Discord si se marca como sospechosa
            if status == 1 then
                SendDiscordLog(
                    "🔍 IP MARCADA MANUALMENTE",
                    "Un administrador marcó la IP **" .. ip .. "** como sospechosa",
                    16776960, -- Amarillo
                    {
                        {
                            ["name"] = "👤 Administrador",
                            ["value"] = GetPlayerName(xPlayer.source) .. " (ID: " .. xPlayer.source .. ")",
                            ["inline"] = true
                        },
                        {
                            ["name"] = "🌐 IP Marcada",
                            ["value"] = "```" .. ip .. "```",
                            ["inline"] = true
                        }
                    }
                )
            end
        end)
    else
        showError("Uso: /markip [ip] [0/1] - 0=no sospechosa, 1=sospechosa")
    end
end, true, {help = "Marcar IP como sospechosa (0=no, 1=si)", validate = true, arguments = {
    {name = 'ip', help = 'Dirección IP', type = 'string'},
    {name = 'status', help = 'Estado: 0 o 1', type = 'string'}
}})

print("^2[ANTI-SPOOF]^0 Sistema anti-spoofing cargado correctamente")