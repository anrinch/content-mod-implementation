from setuptools import setup

setup(
    name="dhf",
    version="0.0.2",
    py_modules=["dhf"],
    package_data={"": ["*.so"]},
    include_package_data=True,
    zip_safe=False,
)
