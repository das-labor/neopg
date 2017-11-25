bench  'dd if=/dev/urandom bs=4M count=20 | src/neopg armor' 'dd if=/dev/urandom bs=4M count=20 | gpg2 --enarmor' --output report.html
bench 'dd if=/dev/urandom bs=4M count=50 | gpg2 --print-md SHA1' 'dd if=/dev/urandom bs=4M count=50 | src/neopg hash --algo SHA-1'
