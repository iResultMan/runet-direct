# RPM around an already built binary (no compiler needed).
#   rpmbuild -bb --target <x86_64|aarch64> \
#     --define "rd_version 1.0.0" --define "rd_binary /path/to/runet-direct" --define "rd_root /path/to/repo" \
#     --define "_topdir /tmp/rpmtop" packaging/linux/runet-direct.spec
Name:           runet-direct
Version:        %{rd_version}
Release:        1
Summary:        Keeps Russian-internet traffic off your VPN
License:        MIT
URL:            https://github.com/iResultMan/runet-direct
Requires:       curl
Requires:       iproute
%global debug_package %{nil}
%global __strip /bin/true

%description
A small background service: traffic to Russian address blocks leaves through
your normal connection while everything else keeps using the VPN. Works with
any VPN, IPv4 and IPv6, repairs its own routes when the network changes.

%install
install -Dm755 %{rd_binary} %{buildroot}/usr/bin/runet-direct
install -Dm644 %{rd_root}/LICENSE %{buildroot}/usr/share/licenses/runet-direct/LICENSE
install -Dm644 %{rd_root}/README.md %{buildroot}/usr/share/doc/runet-direct/README.md
install -Dm644 %{rd_root}/README.ru.md %{buildroot}/usr/share/doc/runet-direct/README.ru.md

%post
if [ -d /run/systemd/system ]; then
    /usr/bin/runet-direct install --in-place --no-wait || echo "runet-direct: service setup failed; run 'sudo runet-direct install --in-place' later" >&2
fi
exit 0

%preun
# $1 is 0 on a real removal and 1 on an upgrade.
if [ "$1" -eq 0 ]; then
    /usr/bin/runet-direct uninstall --in-place || :
fi
exit 0

%files
/usr/bin/runet-direct
%license /usr/share/licenses/runet-direct/LICENSE
%doc /usr/share/doc/runet-direct/README.md
%doc /usr/share/doc/runet-direct/README.ru.md

%changelog
* Wed Oct 14 2026 iResultMan <i.result.man@gmail.com> - 1.0.0-1
- Initial package
