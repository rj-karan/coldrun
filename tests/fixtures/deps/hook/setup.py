# Synthetic sample: overrides the install command so code runs at install time.
# It only prints; it exists to match GuardDog's install-hook rule.
from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        install.run(self)
        print("installed")


setup(name="hookpkg", version="0.1", cmdclass={"install": PostInstall})
