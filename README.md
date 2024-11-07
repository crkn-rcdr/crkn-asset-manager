# CRKN Asset Manager
This python fast-api microservice provides an API for writing access related assets to their datastores.

## Authenticated endpoints
- The asset manager provides a log in flow for front-end applications.
- The asset manager uploads images to our openstack swift object storage, and returns valid IIIF canvas information for that image.
- The asset manager can also provide this functionality for image URLs.
- Finally, it can be used to send secure requests to upload content to the crkn-iiif-presentation-api service.

## Public endpoints
- It allows for retreiving OCR and PDF data for content in our access platform, too.

# Running Locally
```
docker compose up
```
Navigate to [localhost:8000](http://0.0.0.0:8000/docs ) to see the API documentation.
