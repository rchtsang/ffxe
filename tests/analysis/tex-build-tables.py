import os
import shutil
import subprocess

"""
build the analysis table results in latex
"""

if __name__ == "__main__":
    subprocess.run([
        'latexmk', 
        '-outdir=_build/',
        '-aux-directory=_build/',
        '-pdflatex',
        '-shell-escape',
        'tables.tex'
    ])
    shutil.copy('_build/tables.pdf', 'tables.pdf')
    shutil.rmtree('_build')