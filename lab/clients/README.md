# Klienci tła (soho-lab/bg-client:1)

    docker build -t soho-lab/bg-client:1 .
    # w konsoli klienta (GNS3):
    bg.sh >/dev/null 2>&1 &
    beacon.sh >/dev/null 2>&1 &     # tylko jeden klient za R1
    pgrep -fl "bg.sh|beacon.sh"

Uwaga (2026-10-28): to tło RITA nadal ocenia często jako Medium — do pomiaru precyzji
potrzebne bardziej zróżnicowane tło.
