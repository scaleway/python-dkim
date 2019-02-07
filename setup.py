from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

setup(
    name="dkim",
    packages=["exceptions"],
    ext_modules=cythonize([Extension("dkim",
                                     ["./dkim.pyx", "./helpers/dkim_helpers.c"],
                                     libraries=['opendkim'],
                                     include_dirs=["./helpers/include"],
                                     )],
                          )

)
