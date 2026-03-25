# SAFT-GT Pipeline
The SafeSec Attack-Fault Tree Generation Toolchain (SAFT-GT) was created in the [SafeSec Project](https://www.uni-ulm.de/in/sp/research/projects/safesec/).
It generates and analyzes Attack-Fault Trees for cyber-physical systems based on their data flow and the hardware and software components used. Vulnerability databases are crawled to identify possible attacks.

If you use the SAFT-GT pipeline, models, or any part of this repository in your research, please kindly cite our paper:

```bibtex
@article{pekaric2025saftgt,
  title   = {Bridging Safety and Security in Complex Systems: A Model-Based Approach with SAFT-GT Toolchain},
  author  = {Pekaric, Irdin and Groner, Raffaela and Raschke, Alexander and Witte, Thomas and Adigun, Jubril Gbolahan and Felderer, Michael and Tichy, Matthias},
  journal = {Journal of Systems and Software},
  year    = {2026}
}
```

## Contents
The content of this supplement package is structured as follows:
- `/models`  
  contains models used or created by SAFT-GT for our example
- `/saft-msgs`  
  the definition of the ROS messages used to trigger the different phases and to send the calculated MTTF
- `/saft_pipeline`  
  the pipeline integrated in a ROS node
- `/scripts`  
  scripts used in the Docker container for performance measurement and testing.
- `/tools`  
  the tools needed for the different stages of the pipeline:
    - `/tools/data2deploy.jar`
      extracts an initial deployment model from a given dataflow model
    - `/tools/dependency_explorer`
      extracts the dependencies of the components in a given deployment on a specific system
    - `/tools/attackgraphgenerator`  
      tries to find vulnerabilities for given components
    - `/tools/AFTGenerator.jar`  
      generates an AFT from FTs, ATs, Dataflow and Deployment models
    - `/tools/SAFTProject.jar`  
      contains dependencies needed by `AFTGenerator.jar`
    - `/tools/aft2dft.jar`  
      converts an AFT to a DFT


Besides the pipeline itself, we have added the following additional files
- `/grammars`  
  contains the Xtext grammars of all introduced domain-specific languages (DSLs)
- `/workshop_presentations`  
  contains the presentations given at the workshop with experts to evaluate our approach, transcript of discussions, linked survey questions and consent forms.
- `/saft-gt-evaluation_rawdata.xlsx`
  contains the raw results of the performance measurement


In the root folder, a `Dockerfile` can be used to create a ROS container that runs the pipeline in a ROS environment.
This should be started along with the Storm model checker most easily with docker compose and the `docker-compose.yml` file.


## Remarks
- It is not possible to run this package from scratch! You'll need a running ROS system that can be used to extract the dataflow and can be accessed by the `dependency_explorer` to extract the dependencies of the ROS nodes on this particular system.
  Due to Hardware and OS depedencies, it wouldn't make sense to provide this system.
- The `atttackgraphgenerator` can be executed stand-alone by first starting a DB-container with the `/tools/attackgraphgenerator/docker-compose.yml`-file and then fill the database by calling `./init.py`.  
  It might be necessary to add an API key to a file `api.json` with the content `{"key" : "<API-Key goes here>"}`  
  After this initization, the `attackgraphgenerator` can be used by calling `./generate.py` with the parameters `-p` or `-s` followed by a string that is searched only in the CPEs resp. in the descriptions.
  A kind of "batch-processing" is possible by using the parameters `-fp` or `-fs` followed by a filename containing a set of strings to be searched, one per line.

## Contact
If you want further information about this project, its results or the tool pipeline, don't hesitate to contact us via e-mail [alexander.raschke@uni-ulm.de](mailto:alexander.raschke@uni-ulm.de)
  
