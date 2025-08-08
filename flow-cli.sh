#!/bin/bash

API_URL="http://127.0.0.1:9600"
TOKEN="testtoken1"

function curl_api() {
    local endpoint="$1"
    local data="$2"
    if [[ -n "$data" ]]; then
        curl -s -H "Authorization: Bearer $TOKEN" -X POST -d "$data" "$API_URL/$endpoint" | jq
    else
        curl -s -H "Authorization: Bearer $TOKEN" "$API_URL/$endpoint" | jq
    fi
}

function main_menu() {
    while true; do
        echo ""
        echo "==== 🌐 FlowEnricher CLI ===="
        echo "1. /status"
        echo "2. /infoip"
        echo "3. /communities"
        echo "4. /announce"
        echo "5. /withdraw"
        echo "6. /announcements"
        echo "7. /bgpannouncements"
        echo "8. /aspathviz"
        echo "9. /bgpstatus"
        echo "10. /blackhole-list"
        echo "11. /flush"
        echo "0. Exit"
        echo "============================="
        read -rp "Select option: " opt

        case "$opt" in
            1) curl_api "status" ;;
            2)
                read -rp "Enter IP to query (/infoip): " ip
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    curl_api "infoip?ip=$ip"
                else
                    echo "❌ Invalid IPv4 format"
                fi
                ;;
            3) curl_api "communities" ;;
            4)
                read -rp "Enter prefix to announce: " prefix
                curl_api "announce" "{\"prefix\": \"$prefix\"}"
                ;;
            5)
                read -rp "Enter prefix to withdraw: " prefix
                curl_api "withdraw" "{\"prefix\": \"$prefix\"}"
                ;;
            6) curl_api "announcements" ;;
            7) curl_api "bgpannouncements" ;;
            8)
                read -rp "Enter IP for AS path visualization: " ip
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    curl_api "aspathviz?ip=$ip"
                else
                    echo "❌ Invalid IPv4 format"
                fi
                ;;
            9) curl_api "bgpstatus" ;;
            10) curl_api "blackhole-list" ;;
            11) curl_api "flush" ;;
            0) echo "👋 Bye!"; exit 0 ;;
            *) echo "❌ Invalid option";;
        esac
    done
}

main_menu

