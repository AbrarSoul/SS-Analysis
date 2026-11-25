				public Document invoke(File pom, VirtualChannel channel)
						throws IOException, InterruptedException {

					try {
						DocumentBuilder documentBuilder_renamed;
						documentBuilder_renamed = DocumentBuilderFactory.newInstance()
								.newDocumentBuilder();
						return documentBuilder_renamed.parse(pom);

					} catch (SAXException | ParserConfigurationException e) {
						throw new InterruptedException(pom
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}