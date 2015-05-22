#! /bin/bash
#
# Scritto da Dennis Anfossi
#
# Dipendenze: youtube-dl, ffmpeg

musica="$HOME/Musica"

function usage {
	echo "Numero di parametri errato!"
	echo -e "Uso: $0 [URL]\n"
	echo "Questo script estrae l'audio da un video di YouTube (e simili) fornito come parametro."
	echo "Il file audio viene salvato nella cartella $musica."
}

if [ $# -ne 1 ]
then
	usage
	exit 1
fi

cd "$musica"
youtube-dl -x --audio-format mp3 --audio-quality 0 -o "%(title)s.%(ext)s" $1
