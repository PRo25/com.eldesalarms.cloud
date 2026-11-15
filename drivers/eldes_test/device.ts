import Homey from 'homey';

export default class EldesTestDevice extends Homey.Device {

  async onInit() {
    await this.setCapabilityValue('eldes_test_state', 'Hello World');
  }

}
