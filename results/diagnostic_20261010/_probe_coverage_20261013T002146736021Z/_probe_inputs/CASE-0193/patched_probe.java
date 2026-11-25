				public Document invoke(File pom, VirtualChannel channel)
						throws IOException, InterruptedException {

					try {
						DocumentBuilderFactory df = DocumentBuilderFactory.newInstance();
						df.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
						df.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
						DocumentBuilder documentBuilder_renamed = df.newDocumentBuilder();
						return documentBuilder_renamed.parse(pom);

					} catch (SAXException | ParserConfigurationException e) {
						throw new InterruptedException(pom
								.getAbsolutePath()
								+ " is not a valid POM file.");
					}
				}