import Homey from 'homey';

export default class EldesTestDriver extends Homey.Driver {

  async onPairListDevices() {
    return [
      {
        name: 'ELDES Test Device',
        data: {
          id: 'eldes-test-device',
        },
      },
    ];
  }

}
