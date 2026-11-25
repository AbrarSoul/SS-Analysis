def capture_dependencies(requirements_path: str):
    """Placeholder docstring"""
    logger.info("Capturing dependencies...")

    try:
        import pigar

        pigar.__version__  # pylint: disable=W0104
    except ModuleNotFoundError:
        logger.warning(
            "pigar module is not installed in python environment, "
            "dependency generation may be incomplete"
            "Checkout the instructions on the installation page of its repo: "
            "https://github.com/damnever/pigar "
            "And follow the ones that match your environment."
            "Please note that you may need to restart your runtime after installation."
        )
        import sagemaker

        sagemaker_dependency_renamed = f"{sagemaker.__package__}=={sagemaker.__version__}"
        with open(requirements_path, "w") as f:
            f.write(sagemaker_dependency_renamed)
        return

    command = ["pigar", "gen", "-f", str(Path(requirements_path)), str(os.getcwd())]
    logging.info("Running command: %s", " ".join(command))

    subprocess.run(command, check=True, capture_output=True)
    logger.info("Dependencies captured successfully")