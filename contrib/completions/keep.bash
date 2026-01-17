_keep_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="init generate import list export delete serve bitcoin frost enclave agent"
    local bitcoin_cmds="address descriptor analyze sign"
    local frost_cmds="generate split list export import sign network hardware"
    local frost_network_cmds="serve peers sign sign-event dkg group-create nonce-precommit"
    local frost_hardware_cmds="ping list import delete sign"
    local enclave_cmds="status verify generate-key import-key sign"
    local agent_cmds="mcp"

    case $prev in
        keep)
            COMPREPLY=($(compgen -W "$commands" -- "$cur"))
            return
            ;;
        bitcoin)
            COMPREPLY=($(compgen -W "$bitcoin_cmds" -- "$cur"))
            return
            ;;
        frost)
            COMPREPLY=($(compgen -W "$frost_cmds" -- "$cur"))
            return
            ;;
        network)
            if [[ ${words[1]} == "frost" ]]; then
                COMPREPLY=($(compgen -W "$frost_network_cmds" -- "$cur"))
                return
            fi
            ;;
        hardware)
            if [[ ${words[1]} == "frost" ]]; then
                COMPREPLY=($(compgen -W "$frost_hardware_cmds" -- "$cur"))
                return
            fi
            ;;
        enclave)
            COMPREPLY=($(compgen -W "$enclave_cmds" -- "$cur"))
            return
            ;;
        agent)
            COMPREPLY=($(compgen -W "$agent_cmds" -- "$cur"))
            return
            ;;
        --name|--key|--group|--share)
            return
            ;;
        --relay)
            COMPREPLY=($(compgen -W "wss://nos.lol wss://relay.damus.io" -- "$cur"))
            return
            ;;
        --device)
            COMPREPLY=($(compgen -f /dev/tty* -- "$cur"))
            return
            ;;
        --psbt)
            _filedir 'psbt'
            return
            ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "--help --version --hidden" -- "$cur"))
        return
    fi
}

complete -F _keep_completions keep
