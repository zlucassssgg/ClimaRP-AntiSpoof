fx_version 'cerulean'
game 'gta5'

author 'zlucasssgg_'
description 'Sistema de detección de spoofing para ClimaRP'
version '1.0.0'

server_scripts {
    '@mysql-async/lib/MySQL.lua',
    'server.lua'
}

dependencies {
    'es_extended',
    'mysql-async'
}