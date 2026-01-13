#compdef keep

_keep() {
    local -a commands bitcoin_cmds frost_cmds frost_network_cmds frost_hardware_cmds enclave_cmds agent_cmds

    commands=(
        'init:Create encrypted vault'
        'generate:Generate new key'
        'import:Import existing nsec'
        'list:List all keys'
        'export:Export nsec'
        'delete:Delete key'
        'serve:Start NIP-46 remote signer'
        'bitcoin:Bitcoin operations'
        'frost:FROST threshold signatures'
        'enclave:AWS Nitro Enclave operations'
        'agent:Agent operations'
    )

    bitcoin_cmds=(
        'address:Get receive/change address'
        'descriptor:Export watch-only descriptor'
        'analyze:Analyze PSBT'
        'sign:Sign PSBT'
    )

    frost_cmds=(
        'generate:Create threshold key'
        'split:Split existing key'
        'list:List shares'
        'export:Export share'
        'import:Import share'
        'sign:Sign with local shares'
        'network:Network signing operations'
        'hardware:Hardware signer operations'
    )

    frost_network_cmds=(
        'serve:Start signer node'
        'peers:Check online peers'
        'sign:Request signature'
        'sign-event:Sign nostr event'
        'dkg:Distributed key generation'
        'group-create:Create signing group'
        'nonce-precommit:Precommit nonces'
    )

    frost_hardware_cmds=(
        'ping:Test connection'
        'list:List shares on device'
        'import:Import share to hardware'
        'delete:Delete share from device'
        'sign:Sign with hardware'
    )

    enclave_cmds=(
        'status:Check enclave status'
        'verify:Verify attestation'
        'generate-key:Generate key in enclave'
        'import-key:Import key to enclave'
        'sign:Sign message'
    )

    agent_cmds=(
        'mcp:Start MCP server'
    )

    _arguments -C \
        '--help[Show help]' \
        '--version[Show version]' \
        '--hidden[Use hidden volume]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[2] in
                bitcoin)
                    _describe 'bitcoin command' bitcoin_cmds
                    ;;
                frost)
                    if [[ $words[3] == "network" ]]; then
                        _describe 'network command' frost_network_cmds
                    elif [[ $words[3] == "hardware" ]]; then
                        _describe 'hardware command' frost_hardware_cmds
                    else
                        _describe 'frost command' frost_cmds
                    fi
                    ;;
                enclave)
                    _describe 'enclave command' enclave_cmds
                    ;;
                agent)
                    _describe 'agent command' agent_cmds
                    ;;
            esac
            ;;
    esac
}

_keep "$@"
