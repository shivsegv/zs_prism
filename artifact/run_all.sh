#!/bin/sh
# Regenerate all results, figures, numbers and the paper PDF.
set -eu
cd "$(dirname "$0")"
if [ ! -f data/adult.data ]; then
    mkdir -p data
    curl -sL -o data/adult.zip https://archive.ics.uci.edu/static/public/2/adult.zip
    (cd data && unzip -o -q adult.zip)
fi
if [ ! -f data/census/census-income.data ]; then
    mkdir -p data/census
    curl -sL -o data/census/census.zip https://archive.ics.uci.edu/static/public/117/census+income+kdd.zip
    (cd data/census && unzip -o -q census.zip && tar xzf census.tar.gz)
fi
python -m unittest discover -s tests -v
cd experiments
python e3_state.py
python e4_linkage.py
python e4_trace.py
python e5_anon.py
python e6_writes.py
python e2_wan.py
python e1_local.py
python e7_census.py
python e8_sota_settings.py
python make_figures.py
python make_tables.py
cd ../../paper
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
