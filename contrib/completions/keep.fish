set -l commands init generate import list export delete serve bitcoin frost enclave mcp-server

complete -c keep -f

complete -c keep -n "not __fish_seen_subcommand_from $commands" -a init -d 'Create encrypted vault'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a generate -d 'Generate new key'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a import -d 'Import existing nsec'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a list -d 'List all keys'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a export -d 'Export nsec'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a delete -d 'Delete key'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a serve -d 'Start NIP-46 remote signer'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a bitcoin -d 'Bitcoin operations'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a frost -d 'FROST threshold signatures'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a enclave -d 'AWS Nitro Enclave operations'
complete -c keep -n "not __fish_seen_subcommand_from $commands" -a mcp-server -d 'Start MCP server'

complete -c keep -n "__fish_seen_subcommand_from bitcoin" -a address -d 'Get address'
complete -c keep -n "__fish_seen_subcommand_from bitcoin" -a descriptor -d 'Export descriptor'
complete -c keep -n "__fish_seen_subcommand_from bitcoin" -a analyze -d 'Analyze PSBT'
complete -c keep -n "__fish_seen_subcommand_from bitcoin" -a sign -d 'Sign PSBT'

complete -c keep -n "__fish_seen_subcommand_from frost" -a generate -d 'Create threshold key'
complete -c keep -n "__fish_seen_subcommand_from frost" -a split -d 'Split existing key'
complete -c keep -n "__fish_seen_subcommand_from frost" -a list -d 'List shares'
complete -c keep -n "__fish_seen_subcommand_from frost" -a export -d 'Export share'
complete -c keep -n "__fish_seen_subcommand_from frost" -a import -d 'Import share'
complete -c keep -n "__fish_seen_subcommand_from frost" -a sign -d 'Sign with local shares'
complete -c keep -n "__fish_seen_subcommand_from frost" -a network -d 'Network operations'
complete -c keep -n "__fish_seen_subcommand_from frost" -a hardware -d 'Hardware operations'

complete -c keep -n "__fish_seen_subcommand_from enclave" -a status -d 'Check status'
complete -c keep -n "__fish_seen_subcommand_from enclave" -a verify -d 'Verify attestation'
complete -c keep -n "__fish_seen_subcommand_from enclave" -a generate-key -d 'Generate key'
complete -c keep -n "__fish_seen_subcommand_from enclave" -a import-key -d 'Import key'
complete -c keep -n "__fish_seen_subcommand_from enclave" -a sign -d 'Sign message'
complete -c keep -n "__fish_seen_subcommand_from enclave" -a sign-psbt -d 'Sign PSBT'

complete -c keep -l help -d 'Show help'
complete -c keep -l version -d 'Show version'
complete -c keep -l hidden -d 'Use hidden volume'
complete -c keep -l name -d 'Key name'
complete -c keep -l key -d 'Key to use'
complete -c keep -l relay -d 'Relay URL'
complete -c keep -l group -d 'FROST group'
