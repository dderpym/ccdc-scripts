# Bash runs the CLI's built-in completion; native fallback handles filenames.
_ccdcctl_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
printf -v _ccdcctl_command '%q complete' "$_ccdcctl_root/ccdcctl"
for _ccdcctl_path in ccdcctl lab/manage lab/check; do
    complete -o default -C "$_ccdcctl_command" "${_ccdcctl_path##*/}" "./$_ccdcctl_path" "$_ccdcctl_path" "$_ccdcctl_root/$_ccdcctl_path"
done
unset _ccdcctl_root _ccdcctl_command _ccdcctl_path
