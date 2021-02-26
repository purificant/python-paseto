from distutils.core import setup
from distutils.extension import Extension

from Cython.Build import cythonize

libsodium = Extension(
    name="libsodium", sources=["paseto/crypto/libsodium.pyx"], libraries=["sodium"]
)

setup(name="python-paseto", ext_modules=cythonize([libsodium]))
