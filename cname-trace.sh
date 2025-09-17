#!/bin/bash
# cname-trace.sh
# Usage: ./cname-trace.sh A console.aws.amazon.com

domain="$2"

if [ -z "$domain" ]; then
  echo "Usage: $0 <rrtype> <domain>"
  exit 1
fi

while true; do
  dig +trace +noidn +all $1 "$domain"
  cname=$(dig +short +noidn CNAME "$domain" | tail -n 1)
  if [ -n "$cname" ]; then
    domain="$cname"
  else
    break
  fi
done
